//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Directory facts for a Linux account, resolved through NSS and realmd.
//
// The backend that owns an account is found by asking each directory
// service named on the passwd line of nsswitch.conf for the uid with
// `getent -s <service>`; the first that answers owns it, and an account no
// directory service knows, or one /etc/passwd holds, is local. The domain
// comes from the fully-qualified name winbind (CORP\alice) or an Entra ID
// module reports, a NetBIOS domain by the DNS name of its realm, and groups
// from initgroups plus group lookups for all of their ids. An nss_ldap
// (nslcd) name gives no domain: nslcd names an account by its uid
// attribute, which may be an e-mail address (GAP-0730). The
// realm and directory type of a winbind account come from realmd, which any
// account may ask (realm_linux.go).
//
// SSSD serves Active Directory, IPA and plain LDAP domains side by side, and
// the name it gives an account does not say which domain holds it: with
// use_fully_qualified_names = False every domain names its accounts bare, and
// a plain LDAP domain may name them by e-mail address (bob@corp.example.com).
// An SSSD account therefore takes its domain from its SID, which SSSD holds
// for the uid itself (sssd_nss_linux.go): it gets the domain, realm and
// principal of a joined realm only when SSSD holds a user of the same name
// with the same SID in that realm's domain, or in a child domain of it that
// ai_discovery.trusted_ad_child_domains lists. A domain-qualified initgroups
// lookup supplies its groups, including trusted-domain memberships. An
// account without a SID, such as one of a plain LDAP domain, gets no
// realm and no principal (GAP-0497, GAP-0568, GAP-0605).
// UPN and mail need SSSD InfoPipe, which only root may call, so the root
// guardian adds them (enterprisehooks identity spool).

// directoryService describes one NSS passwd service DefenseClaw recognises.
type directoryService struct {
	directory useridentity.Directory
	source    string
}

// directoryServices are the NSS passwd services that name a directory. The
// sss service serves AD, IPA and plain LDAP domains alike, so its directory
// comes from the realm that serves the account's domain.
var directoryServices = map[string]directoryService{
	"sss":        {source: useridentity.SourceSSSD},
	"winbind":    {directory: useridentity.DirectoryActiveDirectory, source: useridentity.SourceWinbind},
	"ldap":       {directory: useridentity.DirectoryLDAP, source: useridentity.SourceNSSLDAP},
	"himmelblau": {directory: useridentity.DirectoryEntraID, source: "himmelblau"},
	"aad":        {directory: useridentity.DirectoryEntraID, source: "nss_aad"},
}

// A cold SSSD answers every group id with a directory query of its own
// (about 30 ms), so one getent call for a few hundred ids outlasts the
// seconds a single command gets, and its failure used to leave the ids as
// numbers that no assignment matches (GAP-0138). The ids are named
// groupQueryBatch at a time, and a batch that fails fails the lookup. The
// batches run one after the other: SSSD fills its cache one request at a
// time, so four getent calls at once each finished only after the calls
// before it, and the last ones ran past the five seconds one command gets
// while the first finished within two (GAP-0230).
const groupQueryBatch = 64

// coldGroupLookup is how long a cold SSSD takes to name one group, and
// directoryLookupBase the budget of the rest of one account's lookups.
var (
	coldGroupLookup     = 30 * time.Millisecond
	directoryLookupBase = 20 * time.Second
)

// DirectoryLookupBudget bounds one resolution of an account's directory
// facts: its account lookups plus the naming of maxDirectoryGroups groups
// one cold SSSD answer at a time. A fixed 20 seconds ran out for an account
// in about 700 groups, which then had no facts until SSSD's cache warmed
// (GAP-1247); the largest membership DefenseClaw names now fits.
func DirectoryLookupBudget() time.Duration {
	return directoryLookupBase + time.Duration(maxDirectoryGroups)*coldGroupLookup
}

// DirectoryFactsForUID resolves the verified directory facts of uid. The
// caller has verified the uid (peer credentials or a per-user credential);
// everything here comes from the host's own account database.
//
// A lookup that does not finish fails as a whole: facts that lack the
// groups, or take a directory account for a local one, would be cached as
// resolved (the gateway keeps them for 15 minutes) and select the default
// profile as though the account had no groups. So does an SSSD NSS
// responder that does not answer, while SSSD is stopped or restarting.
func (r *NSSResolver) DirectoryFactsForUID(uid int, now time.Time) (useridentity.DirectoryFacts, error) {
	return r.directoryFactsForUID(uid, now, true)
}

// DirectoryFactsWithoutGroupsForUID is for the guardian spool. The Linux
// gateway resolves groups itself, so naming them here can consume the time
// reserved for the privileged InfoPipe UPN lookup.
func (r *NSSResolver) DirectoryFactsWithoutGroupsForUID(uid int, now time.Time) (useridentity.DirectoryFacts, error) {
	return r.directoryFactsForUID(uid, now, false)
}

func (r *NSSResolver) directoryFactsForUID(uid int, now time.Time, includeGroups bool) (useridentity.DirectoryFacts, error) {
	account, err := r.LookupUID(uid)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts := useridentity.DirectoryFacts{
		Directory:  useridentity.DirectoryLocal,
		Source:     useridentity.SourceNSSFiles,
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
	}
	// /etc/passwd is authoritative for a matching local name and uid.
	// Check it before directory probes so an unavailable backend cannot
	// make a local account's facts fail.
	local, localErr := LocalAccounts(r.context())
	if localErr != nil && !errors.Is(localErr, os.ErrNotExist) {
		return useridentity.DirectoryFacts{}, localErr
	}
	_, isLocal := local[account.Name]
	isLocal = isLocal && local[account.Name] == uid
	// sssd is the connection to the SSSD NSS responder for an SSSD account,
	// sid the SID SSSD holds for its uid ("" for none) and inDomain the SSSD
	// domain that holds a user of its name with that SID.
	var (
		sssd          *sssdNSS
		sid, inDomain string
	)
	if !isLocal {
		// The facts are those of the service NSS answers the uid from, in
		// the order of the passwd line (passwdOwner): a later service that
		// still holds an older account under the uid, such as SSSD's cache
		// of an account an LDAP or NIS service took the uid over from, names
		// another account's SID, domain and groups (review of GAP-0551).
		// A service DefenseClaw names no directory for (nis, compat) that
		// answers keeps the facts plain.
		service, _, ownerErr := r.passwdOwner(uid)
		if ownerErr != nil && !IsNotFound(ownerErr) {
			return useridentity.DirectoryFacts{}, ownerErr
		}
		if known, ok := directoryServices[service]; ok && ownerErr == nil {
			facts.Directory, facts.Source = known.directory, known.source
			bare, domain := useridentity.SplitQualifiedName(account.Name)
			switch {
			case known.source == useridentity.SourceSSSD:
				if sssd, err = dialSSSDNSS(r.context()); err != nil {
					return useridentity.DirectoryFacts{}, err
				}
				defer sssd.Close()
				if sid, err = sssdAccountSID(sssd, uid); err != nil {
					return useridentity.DirectoryFacts{}, err
				}
				if inDomain, err = r.applySSSDDomain(&facts, sssd, account.Name, sid); err != nil {
					return useridentity.DirectoryFacts{}, err
				}
			case known.source == useridentity.SourceNSSLDAP:
				// nslcd names an account by its uid attribute, which is an
				// e-mail address for the Okta LDAP Interface and for
				// directories that name accounts by mail, so the name gives
				// no domain, realm or principal: an LDAP bob@corp.example.com
				// took the principal of the AD bob (GAP-0730).
			case domain == "":
			case known.directory == useridentity.DirectoryEntraID:
				// The aad module, and Himmelblau with cn_name_mapping =
				// false, name an Entra ID account by its UPN. It has no
				// Kerberos realm, and the UPN is the principal Windows
				// reports for the same user. Himmelblau's default
				// (cn_name_mapping = true) names it by the short name, which
				// carries no domain: such an account has no UPN here
				// (GAP-0328).
				facts.Domain = strings.ToLower(domain)
				facts.UPN = useridentity.NormalizeUPN(account.Name)
				facts.Principal = facts.UPN
			default:
				// winbind: lower case, as Windows reports a NetBIOS domain
				// it knows no DNS name for; applyRealm gives the DNS name
				// of the realm a NetBIOS domain names.
				facts.Domain = strings.ToLower(domain)
				if strings.Contains(domain, ".") {
					facts.Realm = strings.ToUpper(domain)
					// sAMAccountName@REALM, the Kerberos principal winbind
					// accounts authenticate as, in the UPN form.
					facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
				}
			}
		}
	}
	if includeGroups {
		if isLocal {
			// Local account memberships come from the local group database,
			// and from the member lists of a directory that holds no account
			// of that name (localAccountGroupsWithDirectory). A name-only
			// NSS lookup can combine groups of distinct accounts.
			_, facts.Groups, err = r.localAccountGroupsWithDirectory(account)
		} else {
			var ids []int
			var qualified bool
			ids, qualified, err = r.accountGroupIDs(account, inDomain)
			if err == nil && sssd != nil && !qualified {
				ids, err = r.sssdGroupsOfDomain(sssd, ids, account, sidDomain(sid))
			}
			if err == nil {
				facts.Groups, err = r.groupNames(ids)
			}
			if err == nil && sssd != nil {
				facts.OnlyPrimaryGroup, err = sssdListsOnlyPrimaryGroup(sssd, ids, account)
			}
		}
		if err != nil {
			return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: groups of %s: %w", account.Name, err)
		}
	}
	if facts.Source == useridentity.SourceWinbind {
		realms, realmErr := hostRealms(r.context())
		if realmErr != nil {
			return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: realmd lookup: %w", realmErr)
		}
		applyRealm(&facts, account.Name, realms)
		facts.AccountDomain, err = r.winbindAccountDomain(account, realms)
		if err != nil {
			return useridentity.DirectoryFacts{}, err
		}
	}
	return facts, nil
}

// winbindAccountDomain is the NetBIOS domain winbind confirms for an
// account, which a users entry DOMAIN\user names: the domain of the
// DOMAIN\name winbind reports, or, for the bare name winbind reports with
// use default domain = yes, the NetBIOS name of its realm that winbind
// answers with the same uid when asked as NETBIOS\name. A NetBIOS name no
// directory confirms is not taken: the NetBIOS domain of corp.example.com
// may be EXAMPLE, and a guess may name a trusted domain (GAP-0456).
func (r *NSSResolver) winbindAccountDomain(account Account, realms []Realm) (string, error) {
	bare, domain := useridentity.SplitQualifiedName(account.Name)
	if strings.Contains(account.Name, `\`) {
		return domain, nil
	}
	if domain != "" {
		return "", nil
	}
	realm, ok := realmFor("", useridentity.SourceWinbind, realms)
	if !ok {
		return "", nil
	}
	for _, candidate := range netBIOSCandidates(realm.NetBIOS, realm.Domain) {
		held, err := r.LookupUserInService("winbind", candidate+`\`+bare)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			return "", fmt.Errorf("unixidentity: winbind account domain of %s: %w", account.Name, err)
		}
		if held.UID == account.UID {
			return candidate, nil
		}
	}
	return "", nil
}

// sssdAccountDomain is the NetBIOS (flat) name of the Active Directory
// domain SSSD confirmed an account in by its SID: a candidate SSSD holds
// the same SID for when asked as FLAT\name. The candidates are the flat
// domain of the account own name (full_name_format = %3$s\%1$s), the
// realm NetBIOS name, the Samba workgroup and the first label of the DNS
// domain, and then the flat name the domain's controllers announce
// (domainShort, adcli info), which the others miss when the first label is
// longer than 15 characters (an Entra Domain Services domain) or is not the
// NetBIOS name (GAP-1095). Only the answer of SSSD confirms one, so a first
// label is never taken on its own (GAP-0456).
func sssdAccountDomain(sssd *sssdNSS, name, dnsDomain, netBIOS, sid string, domainShort func(string) (string, error)) (string, error) {
	bare, nameDomain := useridentity.SplitQualifiedName(name)
	var candidates []string
	if strings.Contains(name, `\`) && !strings.Contains(nameDomain, ".") {
		candidates = append(candidates, nameDomain)
	}
	candidates = append(candidates, netBIOSCandidates(netBIOS, dnsDomain)...)
	confirm := func(candidate string) (bool, error) {
		held, err := sssd.sidOfUserInDomain(candidate, bare)
		if err != nil {
			return false, fmt.Errorf("unixidentity: SSSD account domain of %s in %s: %w", bare, candidate, err)
		}
		return held != "" && strings.EqualFold(held, sid), nil
	}
	for _, candidate := range candidates {
		if ok, err := confirm(candidate); err != nil {
			return "", err
		} else if ok {
			return candidate, nil
		}
	}
	if domainShort == nil {
		return "", nil
	}
	short, err := domainShort(dnsDomain)
	if err != nil {
		return "", err
	}
	announced := strings.TrimSpace(short)
	if !validNetBIOSCandidate(announced) || slices.ContainsFunc(candidates, func(seen string) bool { return strings.EqualFold(seen, announced) }) {
		return "", nil
	}
	if ok, err := confirm(announced); err != nil || !ok {
		return "", err
	}
	return strings.ToUpper(announced), nil
}

// netBIOSCandidates lists the NetBIOS names a joined domain may have, to be
// confirmed by its directory: the one realmd reports, the Samba workgroup
// and the upper-cased first label of the DNS domain.
func netBIOSCandidates(netBIOS, dnsDomain string) []string {
	first, _, _ := strings.Cut(dnsDomain, ".")
	var out []string
	for _, candidate := range []string{netBIOS, sambaWorkgroup(), strings.ToUpper(first)} {
		candidate = strings.TrimSpace(candidate)
		if !validNetBIOSCandidate(candidate) ||
			slices.ContainsFunc(out, func(seen string) bool { return strings.EqualFold(seen, candidate) }) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

// validNetBIOSCandidate accepts a name that can be a NetBIOS domain: 1 to 15
// characters, none of them a separator.
func validNetBIOSCandidate(candidate string) bool {
	return candidate != "" && len(candidate) <= 15 && !strings.ContainsAny(candidate, `\/@. :,`)
}

// adcliPaths are where adcli, the tool realm join uses to join an Active
// Directory domain for SSSD, is installed; adcliTool picks the trusted one
// (replaceable in tests).
var (
	adcliPaths = []string{"/usr/sbin/adcli", "/usr/bin/adcli"}
	adcliTool  = func() (string, error) { return firstTrustedTool(adcliPaths...) }
)

// adcliAnswerTimeout bounds one adcli info call; adcliRetryAfter is how long
// a domain whose controllers did not announce a flat name is not asked
// again.
const (
	adcliAnswerTimeout = 3 * time.Second
	adcliRetryAfter    = 10 * time.Minute
)

// adcliShortNames keeps the flat name each domain's controllers announced,
// for the process, and when a domain's did not answer.
var adcliShortNames struct {
	sync.Mutex
	byDomain map[string]adcliShortName
}

type adcliShortName struct {
	short    string
	failedAt time.Time
}

// adcliDomainShort is the NetBIOS (flat) name the controllers of dnsDomain
// announce, as adcli info prints it (domain-short). If adcli is installed,
// an execution failure is returned to the caller and not cached, so incomplete
// directory facts cannot be cached as verified. A successful answer with no
// flat name is cached briefly.
func (r *NSSResolver) adcliDomainShort(dnsDomain string) (string, error) {
	dnsDomain = strings.ToLower(strings.TrimSpace(dnsDomain))
	if dnsDomain == "" || strings.HasPrefix(dnsDomain, "-") || strings.ContainsAny(dnsDomain, " \t\x00\r\n/\\@") {
		return "", nil
	}
	adcliShortNames.Lock()
	known, ok := adcliShortNames.byDomain[dnsDomain]
	adcliShortNames.Unlock()
	if ok && (known.short != "" || time.Since(known.failedAt) < adcliRetryAfter) {
		return known.short, nil
	}
	path, err := adcliTool()
	if err != nil {
		// adcli is optional on hosts whose NSS and realmd data suffice.
		return "", nil
	}
	ctx, cancel := context.WithTimeout(r.context(), adcliAnswerTimeout)
	result, err := r.runner(ctx, path, []string{"info", dnsDomain})
	cancel()
	if err != nil {
		return "", fmt.Errorf("unixidentity: adcli info of %s: %w", dnsDomain, err)
	}
	if result.exitCode != 0 {
		return "", fmt.Errorf("unixidentity: adcli info of %s exited %d", dnsDomain, result.exitCode)
	}
	answer := adcliShortName{short: parseADCLIDomainShort(string(result.stdout)), failedAt: time.Now()}
	adcliShortNames.Lock()
	if adcliShortNames.byDomain == nil {
		adcliShortNames.byDomain = map[string]adcliShortName{}
	}
	adcliShortNames.byDomain[dnsDomain] = answer
	adcliShortNames.Unlock()
	return answer.short, nil
}

// parseADCLIDomainShort reads "domain-short = NAME" of adcli info output.
func parseADCLIDomainShort(output string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "domain-short" {
			return strings.ToUpper(strings.TrimSpace(value))
		}
	}
	return ""
}

// sambaWorkgroup reads the workgroup of the [global] section of smb.conf,
// the NetBIOS domain a winbind join writes, or "".
func sambaWorkgroup() string {
	data, err := readSmallFile(sambaConfPath, 1<<20)
	if err != nil {
		return ""
	}
	return strings.ToUpper(sambaGlobal(string(data), "workgroup"))
}

// sambaGlobal reads the value of key in the [global] section of smb.conf
// content, or "". Samba compares parameter names without regard to case or
// spacing.
func sambaGlobal(content, key string) string {
	global := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			global = strings.EqualFold(strings.Trim(line, "[] \t"), "global")
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if global && ok && strings.EqualFold(strings.Join(strings.Fields(name), " "), key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// applySSSDDomain gives an SSSD account the domain, realm, directory type
// and principal of the joined realm that holds it, and returns the SSSD
// domain that confirmed it ("" for none). A joined realm holds the account
// when SSSD holds a SID for the uid and a user of the account's name with
// that same SID in the realm's domain, asked in the domain\name form, which
// SSSD looks up in that domain only (sidOfUserInDomain). A qualified name
// (use_fully_qualified_names = True, what realm join writes) is asked in the
// domain it names. A child domain of a joined realm holds accounts of that
// realm only when the administrator lists it in
// ai_discovery.trusted_ad_child_domains (sssdRealmFor): a plain LDAP domain
// can carry a name below the joined domain and SIDs of its own, so neither
// the name nor a SID proves a trusted child (GAP-1255). A short name is asked
// in each joined SSSD realm and each listed child. The same SID is the same account,
// so the realm, principal and groups of an account never go to another
// account that only shares its name: a plain LDAP account of the same short
// name, one named by an e-mail address in the joined domain, or one SSSD
// finds through a UPN or e-mail search. An account without a SID, or one no
// joined realm holds, gets no realm, principal or directory type, and no
// domain from a name that only looks qualified (bob@corp.example.com in a
// plain LDAP domain).
func (r *NSSResolver) applySSSDDomain(facts *useridentity.DirectoryFacts, sssd *sssdNSS, name, sid string) (string, error) {
	bare, domain := useridentity.SplitQualifiedName(name)
	if domain != "" && !strings.Contains(domain, ".") && !strings.Contains(name, `\`) {
		// The SSSD name of a domain with no DNS name, which names no realm.
		// A DOMAIN\name gets no domain from its name: a plain LDAP domain may
		// name an account so, as nslcd may (GAP-0814); SSSD confirms the
		// domain of an AD account by its SID below.
		facts.Domain = strings.ToLower(domain)
	}
	if sidDomain(sid) == "" {
		return "", nil
	}
	realms, err := hostRealms(r.context())
	if err != nil {
		return "", fmt.Errorf("unixidentity: realmd lookup: %w", err)
	}
	var candidates []string
	if strings.Contains(domain, ".") {
		candidates = []string{strings.ToLower(domain)}
	} else {
		for _, realm := range realms {
			if strings.EqualFold(realm.ClientSoftware, "sssd") && realm.Domain != "" {
				candidates = append(candidates, realm.Domain)
			}
		}
		// Under use_fully_qualified_names = False a listed child domain
		// names its accounts bare too.
		for _, child := range useridentity.TrustedADChildDomains() {
			if _, ok := sssdRealmFor(child, realms); ok && !slices.Contains(candidates, child) {
				candidates = append(candidates, child)
			}
		}
	}
	for _, candidate := range candidates {
		held, err := sssd.sidOfUserInDomain(candidate, bare)
		if err != nil {
			return "", fmt.Errorf("unixidentity: SSSD SID of %s in %s: %w", bare, candidate, err)
		}
		if !strings.EqualFold(held, sid) {
			continue
		}
		realm, ok := sssdRealmFor(candidate, realms)
		if !ok {
			continue
		}
		facts.Domain = candidate
		facts.Realm = strings.ToUpper(candidate)
		if candidate == realm.Domain && realm.Name != "" {
			facts.Realm = realm.Name
		}
		facts.Directory = realmDirectory(realm)
		facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
		facts.AccountDomain, err = sssdAccountDomain(sssd, name, candidate, realm.NetBIOS, sid, r.adcliDomainShort)
		if err != nil {
			return "", err
		}
		return candidate, nil
	}
	return "", nil
}

// sssdAccountSID returns the SID SSSD holds for the user with uid, "" for
// none. A SID that SSSD maps back to another uid is not the account's: a
// domain that copies the SIDs of another domain holds the uid, not the SID.
func sssdAccountSID(sssd *sssdNSS, uid int) (string, error) {
	sid, err := sssd.sidByUID(uid)
	if err != nil {
		return "", fmt.Errorf("unixidentity: SSSD SID of uid %d: %w", uid, err)
	}
	if sid == "" {
		return "", nil
	}
	mapped, err := sssd.uidOfSID(sid)
	if err != nil {
		return "", fmt.Errorf("unixidentity: SSSD uid of %s: %w", sid, err)
	}
	if mapped != uid {
		return "", nil
	}
	return sid, nil
}

// accountGroupIDs lists the groups of account with initgroups. An SSSD
// account a joined domain confirmed is asked for in the domain\name form,
// which SSSD looks up in that domain only: by its short name SSSD may find
// another domain's account of that name and list its groups (GAP-0563).
// The files module matches no /etc/group member to that form, so the
// /etc/group groups that list the account by its passwd name, the groups the
// OS gives it at login, are read from /etc/group (GAP-0729), when the OS
// reads /etc/group at login at all: the initgroups services of
// nsswitch.conf name files. Without that a membership in /etc/group that
// login ignores selected a group profile (GAP-1280). Its name
// qualified with the domain is not matched: under short names that is the
// passwd name of an account a domain names by e-mail address, and a group
// listing it is that account's. The boolean reports whether the
// domain-qualified query succeeded, so its trusted-domain groups are kept.
func (r *NSSResolver) accountGroupIDs(account Account, inDomain string) ([]int, bool, error) {
	bare, _ := useridentity.SplitQualifiedName(account.Name)
	if inDomain != "" {
		ids, err := r.rawGroupIDs(Account{Name: inDomain + `\` + bare, GID: account.GID})
		if !IsNotFound(err) {
			if err != nil {
				return nil, false, err
			}
			services, err := nssInitgroupsServices()
			if err != nil {
				return nil, false, err
			}
			var local []int
			if nssReadsLocalGroups(services) {
				accounts, lookupErr := LocalAccounts(r.context())
				if lookupErr != nil && !errors.Is(lookupErr, os.ErrNotExist) {
					return nil, false, lookupErr
				}
				if uid, found := accounts[account.Name]; !found || uid == account.UID {
					if local, err = localGroupsListing(account.Name); err != nil {
						return nil, false, err
					}
				}
			}
			ids = append(ids, local...)
			slices.Sort(ids)
			return slices.Compact(ids), true, nil
		}
	}
	ids, err := r.GroupIDs(account)
	return ids, false, err
}

// sssdGroupsOfDomain limits groups from an ambiguous, unqualified
// initgroups lookup to the SSSD account domain, the domain of its SID.
// A successful domain-qualified lookup is authoritative and skips this
// filter. The primary group always counts. An SSSD group counts when its SID
// belongs to the account's domain, or when neither account nor group has a
// SID. A SID-less group of a SID-bearing account counts only if /etc/group
// lists the account as a member or another configured NSS initgroups service
// confirms its membership without resolving the name to a different uid.
// This keeps LDAP-supplied groups for the account's uid.
func (r *NSSResolver) sssdGroupsOfDomain(sssd *sssdNSS, ids []int, account Account, domainSID string) ([]int, error) {
	localAccounts, err := LocalAccounts(r.context())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	localUID, localNameExists := localAccounts[account.Name]
	nameSharedWithLocal := localNameExists && localUID != account.UID
	var localIDs []int
	if !nameSharedWithLocal {
		localIDs, err = localGroupsListing(account.Name)
		if err != nil {
			return nil, err
		}
	}
	local := make(map[int]bool, len(localIDs))
	for _, id := range localIDs {
		local[id] = true
	}
	sids := make(map[int]string, len(ids))
	needOther := false
	for _, id := range ids {
		if id == account.GID {
			continue
		}
		sid, err := sssd.sidByGID(id)
		if err != nil {
			return nil, fmt.Errorf("SSSD SID of gid %d: %w", id, err)
		}
		sids[id] = sid
		if sid == "" && domainSID != "" && !local[id] {
			needOther = true
		}
	}
	var other map[int]bool
	if needOther && !nameSharedWithLocal {
		other, err = r.otherNSSGroupMemberships(account)
		if err != nil {
			return nil, err
		}
	}
	kept := make([]int, 0, len(ids))
	for _, id := range ids {
		sid := sids[id]
		if id == account.GID ||
			(sid != "" && domainSID != "" && sidDomain(sid) == domainSID) ||
			(sid == "" && (domainSID == "" || local[id] || other[id])) {
			kept = append(kept, id)
		}
	}
	return kept, nil
}

// sssdDomainUsersRID ends the SID of an Active Directory domain's Domain
// Users group, the primary group of its accounts in the directory.
const sssdDomainUsersRID = "-513"

// sssdListsOnlyPrimaryGroup reports whether the groups SSSD lists for an
// account are only its primary group, the Domain Users group of its domain
// (its directory primary group, when SSSD gives the account a private group)
// and the /etc/group groups that list it. While SSSD cannot reach the
// directory it answers from its cache, and for an account whose memberships
// it never looked up (a first sign-in during the outage, or a cleared cache)
// that answer is the primary group alone, with nothing to say the rest is
// missing (GAP-0191). An account in no other group gets the same answer. A
// SID lookup that fails says nothing, and the groups count as listed.
func sssdListsOnlyPrimaryGroup(sssd *sssdNSS, ids []int, account Account) (bool, error) {
	local, err := localGroupsListing(account.Name)
	if err != nil {
		return false, err
	}
	var others []int
	for _, id := range ids {
		if id != account.GID && !slices.Contains(local, id) {
			others = append(others, id)
		}
	}
	switch len(others) {
	case 0:
		return true, nil
	case 1:
		sid, err := sssd.sidByGID(others[0])
		return err == nil && sid != "" && strings.HasSuffix(sid, sssdDomainUsersRID), nil
	}
	return false, nil
}

// otherNSSGroupMemberships asks each configured non-SSSD initgroups service
// for this account's groups when that service does not resolve the name to a
// different uid. Looking up a group by gid alone would prove only that the
// group exists, not that the account belongs to it.
func (r *NSSResolver) otherNSSGroupMemberships(account Account) (map[int]bool, error) {
	services, err := nssInitgroupsServices()
	if err != nil || services == nil {
		return nil, err // no list: glibc defaults to files
	}
	groups := map[int]bool{}
	for _, service := range services {
		if service == "sss" || service == "files" || !validServiceName(service) {
			continue
		}
		if memberListServices[service] {
			listed, skip, err := r.memberListGroupsOf(service, account)
			if err != nil {
				return nil, err
			}
			if !skip {
				for _, id := range listed {
					groups[id] = true
				}
			}
			continue
		}
		byName, err := r.LookupUserInService(service, account.Name)
		if err != nil && !IsNotFound(err) {
			return nil, err
		}
		if err == nil && byName.UID != account.UID {
			continue
		}
		ids, err := r.groupIDsInService(service, account.Name)
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			groups[id] = true
		}
	}
	return groups, nil
}

// nssInitgroupsServices is the service list glibc uses for initgroups: the
// initgroups line of nsswitch.conf, else its group line (nssServicesInUse:
// compat asks its included services only for the + lines of /etc/group); nil
// without either line or without the file, which glibc reads as files.
func nssInitgroupsServices() ([]string, error) {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unixidentity: read NSS configuration: %w", err)
	}
	services := ParseNSSwitchServices(string(data), "initgroups")
	if len(services) == 0 {
		services = nssServicesInUse(string(data), "group", localGroupPath)
	}
	return services, nil
}

// nssReadsLocalGroups reports whether initgroups reads /etc/group with the
// services nssInitgroupsServices returned: files, or compat, which reads it
// too; glibc's default (no list) is files.
func nssReadsLocalGroups(services []string) bool {
	return len(services) == 0 || slices.Contains(services, "files") || slices.Contains(services, "compat")
}

// localAccountGroups lists a local account's primary and supplementary gids
// and names in one reading of the local group database. A gid not named there
// stays numeric; a directory group with that gid cannot name a local member.
func localAccountGroups(account Account) ([]int, []string, error) {
	services, err := nssInitgroupsServices()
	if err != nil {
		return nil, nil, err
	}
	data, err := readSmallFile(localGroupPath, 16<<20)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	ids := []int{account.GID}
	namesByID := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		gid, name, ok := parseGroupName(line)
		if !ok {
			continue
		}
		if _, seen := namesByID[gid]; !seen {
			namesByID[gid] = name
		}
		if !nssReadsLocalGroups(services) {
			continue
		}
		members := strings.Split(line, ":")[3]
		if slices.ContainsFunc(strings.Split(members, ","), func(member string) bool {
			return strings.TrimLeft(member, " \t\n\v\f\r") == account.Name
		}) {
			ids = append(ids, gid)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) > maxDirectoryGroups {
		return nil, nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
	}
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := namesByID[id]; name != "" {
			names = append(names, name)
		} else {
			names = append(names, strconv.Itoa(id))
		}
	}
	return ids, names, nil
}

// memberListServices are the NSS group services that list a group's
// members by account name (RFC 2307 memberUid, NIS member lists), whether
// or not that directory holds an account of the name: such a group may list
// a local account. sss, winbind and the Entra ID modules answer initgroups
// only for an account of their own.
var memberListServices = map[string]bool{"ldap": true, "nis": true, "nisplus": true}

// localAccountGroupsWithDirectory is localAccountGroups for a local account,
// plus the groups a member-list directory (memberListServices) lists it in
// and the directory's names of the gids /etc/group does not name (GAP-0550).
// A service that resolves the name to another uid is skipped: its answer is
// that account's. A directory that does not answer fails the lookup, as it
// does for a directory account: the groups it would list are unknown, and
// facts without them could select a less strict profile than the account's
// (fail closed). So does one that holds no account of the name, lists the
// name in no group and cannot show that it answers at all, which is how
// getent reports an nslcd that cannot reach LDAP (memberListGroupsOf).
func (r *NSSResolver) localAccountGroupsWithDirectory(account Account) ([]int, []string, error) {
	ids, names, err := localAccountGroups(account)
	if err != nil {
		return nil, nil, err
	}
	services, err := nssInitgroupsServices()
	if err != nil {
		return nil, nil, err
	}
	named := make(map[int]string, len(ids))
	for i, id := range ids {
		if names[i] != strconv.Itoa(id) {
			named[id] = names[i]
		}
	}
	extra := false
	for _, service := range services {
		if !memberListServices[service] || !validServiceName(service) {
			continue
		}
		listed, skip, listErr := r.memberListGroupsOf(service, account)
		if listErr != nil {
			return nil, nil, listErr
		}
		if skip {
			continue
		}
		for _, id := range listed {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
				extra = true
			}
		}
	}
	if extra {
		slices.Sort(ids)
		if len(ids) > maxDirectoryGroups {
			return nil, nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
		}
	}
	var unnamed []int
	for _, id := range ids {
		if _, ok := named[id]; !ok {
			unnamed = append(unnamed, id)
		}
	}
	if len(unnamed) > 0 && slices.ContainsFunc(services, func(service string) bool { return service != "files" }) {
		resolved, nameErr := r.groupNames(unnamed)
		if nameErr != nil {
			return nil, nil, nameErr
		}
		for i, id := range unnamed {
			if resolved[i] != strconv.Itoa(id) {
				named[id] = resolved[i]
			}
		}
	}
	names = make([]string, 0, len(ids))
	for _, id := range ids {
		if name, ok := named[id]; ok {
			names = append(names, name)
		} else {
			names = append(names, strconv.Itoa(id))
		}
	}
	return ids, names, nil
}

// errDirectoryUnconfirmed marks a directory answer DefenseClaw cannot tell
// from an outage: getent exits 2 for a name both when a directory holds no
// such account and when its module cannot answer (nslcd that cannot reach
// LDAP, ypbind or winbindd down, SSSD stopped), and initgroups succeeds with
// no group in both cases.
var errDirectoryUnconfirmed = errors.New("the directory did not show that it answers")

// memberListGroupsOf returns the gids the member-list service (ldap, nis,
// nisplus) lists account's name in; skip is set when the service holds
// another account of that name, whose groups those are. An answer that names
// neither the account nor a group counts only once the service shows it is
// answering (serviceAnswers): otherwise a strict profile's LDAP group was
// dropped while nslcd could not reach LDAP, and the account got a weaker
// profile (review of GAP-0550).
func (r *NSSResolver) memberListGroupsOf(service string, account Account) ([]int, bool, error) {
	holder, err := r.LookupUserInService(service, account.Name)
	if err != nil && !IsNotFound(err) {
		return nil, false, fmt.Errorf("%s account %s: %w", service, account.Name, err)
	}
	if err == nil && holder.UID != account.UID {
		return nil, true, nil
	}
	answered := err == nil
	listed, err := r.groupIDsInService(service, account.Name)
	if err != nil && !IsNotFound(err) {
		return nil, false, err
	}
	if !answered && len(listed) == 0 {
		if err := r.serviceAnswers(service); err != nil {
			return nil, false, fmt.Errorf("unixidentity: %s groups of %s: %w", service, account.Name, err)
		}
	}
	return listed, false, nil
}

// confirmMemberListGroups returns ids, the groups all initgroups services
// list together, once each member-list service among them shows that it
// answers for account (memberListGroupsOf): the combined answer silently
// lacks the groups an unreachable nslcd or ypbind lists.
func (r *NSSResolver) confirmMemberListGroups(account Account, services []string, ids []int) ([]int, error) {
	asked := map[string]bool{}
	for _, service := range services {
		if !memberListServices[service] || !validServiceName(service) || asked[service] {
			continue
		}
		asked[service] = true
		if _, _, err := r.memberListGroupsOf(service, account); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// serviceAnswers reports, with nil, that NSS service lists at least one
// group or account when asked to enumerate them, which shows that it
// answers. Only the first entry is read (firstEntry). A directory that does
// not enumerate (nslcd with nss_disable_enumeration) cannot show it, and its
// empty answers stay unconfirmed (fail closed).
func (r *NSSResolver) serviceAnswers(service string) error {
	if !validServiceName(service) {
		return fmt.Errorf("unixidentity: invalid NSS service %q", service)
	}
	for _, database := range []string{"group", "passwd"} {
		sample := &firstEntry{}
		filters := []outputFilter{sample.wrap}
		if database == "group" {
			filters = append(filters, withoutGroupMembers)
		}
		result, err := r.runner(r.context(), r.path, []string{"-s", service, database}, filters...)
		line := sample.line
		if line == "" && err == nil && result.exitCode == getentExitOK {
			if lines := nonEmptyLines(string(result.stdout)); len(lines) > 0 {
				line = lines[0]
			}
		}
		if database == "group" {
			if _, _, ok := parseGroupName(line); ok {
				return nil
			}
		} else if _, parseErr := ParsePasswdLine(line); line != "" && parseErr == nil {
			return nil
		}
	}
	return fmt.Errorf("unixidentity: NSS service %s lists no group or account: %w", service, errDirectoryUnconfirmed)
}

// errEnumerationSampled ends an enumeration once its first entry is read.
var errEnumerationSampled = errors.New("unixidentity: enumeration sampled")

// firstEntry keeps the first line a command writes and fails every write
// after it, which closes the pipe and ends the command: one entry shows that
// a directory answers, and listing the rest of a large one would take its
// time and pass the output limit.
type firstEntry struct {
	partial []byte
	line    string
	done    bool
}

func (f *firstEntry) wrap(io.Writer) io.Writer { return f }

func (f *firstEntry) Write(p []byte) (int, error) {
	if f.done {
		return 0, errEnumerationSampled
	}
	end := bytes.IndexByte(p, '\n')
	if end < 0 {
		if len(f.partial)+len(p) > defaultOutputLimit {
			return 0, errOutputLimit
		}
		f.partial = append(f.partial, p...)
		return len(p), nil
	}
	f.line = strings.TrimRight(string(append(f.partial, p[:end]...)), "\r")
	f.done = true
	return 0, errEnumerationSampled
}

// localGroupsListing returns the gids of the /etc/group entries whose member
// list names name, split and compared as the glibc files module does, so
// DefenseClaw and id(1) agree: white space before each member is skipped,
// and only the newline ends the line, so the CR of a CRLF line stays in its
// last member, which then names no account (GAP-0815). A missing file holds
// none.
func localGroupsListing(name string) ([]int, error) {
	data, err := readSmallFile(localGroupPath, 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, line := range strings.Split(string(data), "\n") {
		gid, _, ok := parseGroupName(line)
		if !ok {
			continue
		}
		members := strings.Split(line, ":")[3]
		if slices.ContainsFunc(strings.Split(members, ","), func(member string) bool {
			return strings.TrimLeft(member, " \t\n\v\f\r") == name
		}) {
			ids = append(ids, gid)
		}
	}
	return ids, nil
}

// groupNames names group ids with getent group calls of groupQueryBatch ids
// each, one after the other. An id no group answers for is kept as its
// number.
func (r *NSSResolver) groupNames(ids []int) ([]string, error) {
	if len(ids) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
	}
	names := make(map[int]string, len(ids))
	for start := 0; start < len(ids); start += groupQueryBatch {
		found, queryErr := r.groupBatchNames(ids[start:min(start+groupQueryBatch, len(ids))])
		if queryErr != nil {
			return nil, queryErr
		}
		maps.Copy(names, found)
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := names[id]; name != "" {
			out = append(out, name)
		} else {
			out = append(out, strconv.Itoa(id))
		}
	}
	return out, nil
}

// groupBatchNames asks one getent group call for the names of ids. The
// member lists getent prints are dropped as they arrive (query), so a batch
// of large directory groups stays within the output limit.
func (r *NSSResolver) groupBatchNames(ids []int) (map[int]string, error) {
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, strconv.Itoa(id))
	}
	result, err := r.query("group", keys...)
	if err != nil {
		return nil, err
	}
	// Exit 2 means some id has no group, which stays a number.
	if result.exitCode != getentExitOK && result.exitCode != getentExitNotFound {
		return nil, fmt.Errorf("getent group exited %d", result.exitCode)
	}
	names := make(map[int]string, len(ids))
	for _, line := range nonEmptyLines(string(result.stdout)) {
		if gid, name, ok := parseGroupName(line); ok {
			names[gid] = name
		}
	}
	return names, nil
}

// ParseNSSwitchServices lists the services on the line of database
// ("passwd", "group") of an nsswitch.conf, in order, lower-cased, without
// actions. The compat service of passwd, group and shadow reads the local
// file and the services of the database's _compat line in its place (nis
// when there is none), so it is listed as "files" followed by those: an SSSD
// account included with a "+" line through passwd_compat: sss was taken for
// a local account (GAP-1123).
func ParseNSSwitchServices(content, database string) []string {
	services := nssSwitchLine(content, database)
	switch database {
	case "passwd", "group", "shadow":
	default:
		return services
	}
	var out []string
	for _, service := range services {
		if service != "compat" {
			out = append(out, service)
			continue
		}
		included := nssSwitchLine(content, database+"_compat")
		if included == nil {
			included = []string{"nis"}
		}
		out = append(out, "files")
		out = append(out, included...)
	}
	return out
}

// nssSwitchLine lists the services of one database line of nsswitch.conf.
func nssSwitchLine(content, database string) []string {
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, sources, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(key) != database {
			continue
		}
		var out []string
		for _, source := range strings.Fields(sources) {
			if !strings.HasPrefix(source, "[") {
				out = append(out, strings.ToLower(source))
			}
		}
		return out
	}
	return nil
}

// Group lookups by name.
//
// Profile assignments name groups, and the gateway warns when the host does
// not know a group by the name an assignment spells (renamed or deleted in
// the directory). Two directory setups make that answer misleading:
//
//   - Himmelblau answers an Entra group only by gid or object id: `getent
//     group NAME` finds nothing by design, while `id` and initgroups name the
//     group. Its "no such group" by name says nothing (GAP-0292).
//   - SSSD joined with realm join names groups name@domain
//     (use_fully_qualified_names = True), so the short name an assignment
//     spells is unknown while the qualified one exists (GAP-0332).

// groupNameUnsearchableServices are NSS group services that cannot look a
// group up by its name.
var groupNameUnsearchableServices = map[string]bool{"himmelblau": true}

// GroupNameLookupDefinitive reports whether a "no such group" answer to a
// lookup by name is definitive on this host: false when the group line of
// nsswitch.conf names a service that cannot look groups up by name, or the
// file cannot be read.
func GroupNameLookupDefinitive() bool {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	for _, service := range ParseNSSwitchServices(string(data), "group") {
		if groupNameUnsearchableServices[service] {
			return false
		}
	}
	return true
}

// GroupDirectoryUsesWinbind reports whether this host looks directory groups
// up through winbind rather than SSSD: the group line of nsswitch.conf names
// winbind and not sss. Advice for a directory that does not answer names the
// service the host uses (GAP-0712).
func GroupDirectoryUsesWinbind() bool {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return false
	}
	winbind := false
	for _, service := range ParseNSSwitchServices(string(data), "group") {
		switch service {
		case "sss":
			return false
		case "winbind":
			winbind = true
		}
	}
	return winbind
}

// QualifiedGroupName returns name@domain, as the host spells it, for the
// first realm the host is joined to (realmd) that has a group of that name,
// or "" when name is already qualified or no realm has it.
func QualifiedGroupName(ctx context.Context, r Resolver, name string) string {
	if r == nil || name == "" || strings.ContainsAny(name, `@\`) {
		return ""
	}
	realms, err := hostRealms(ctx)
	if err != nil {
		return ""
	}
	for _, realm := range realms {
		if realm.Domain == "" {
			continue
		}
		if listed := GroupSpelling(r, name+"@"+realm.Domain); listed != "" {
			return listed
		}
	}
	return ""
}

// QualifiedUserName finds the spelling NSS accepts for a short account name
// on a joined host configured to require fully qualified names.
func QualifiedUserName(ctx context.Context, r Resolver, name string) string {
	if r == nil || name == "" || strings.ContainsAny(name, `@\`) {
		return ""
	}
	realms, err := hostRealms(ctx)
	if err != nil {
		return ""
	}
	for _, realm := range realms {
		for _, candidate := range []string{name + "@" + realm.Domain, realm.NetBIOS + `\` + name} {
			if candidate == name+"@" || strings.HasPrefix(candidate, `\`) {
				continue
			}
			if _, err := r.LookupUser(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}

// SameNameAccounts lists the other accounts the host holds under the bare
// name of account: the account NSS answers that bare name with, the account
// each passwd service of nsswitch.conf answers it with when asked on its
// own, and the directory account of each joined domain NSS answers
// name@domain or NETBIOS\name with. A local and a directory account of one
// name are two accounts (twins); an answer counts only when its own bare name
// is that name and its uid is not account's (GAP-1087).
//
// NSS answers a bare name with the first service that holds it, so with
// passwd: files ldap the LDAP alice behind the local one, and the local
// account behind an SSSD one, showed only when that service was asked on its
// own. A service's "no such account" counts only when it shows that it
// answers (passwdServiceAnswers): getent says the same while nslcd, ypbind,
// winbindd or SSSD cannot answer. The joined domains are the ones realmd
// lists together with every other source DefenseClaw can read
// (sameNameRealms). While a twin may exist that DefenseClaw cannot look up (a
// service that does not show it answers, a domain list that may be
// incomplete, a lookup that failed rather than found nothing) and none was
// found, the answer is a *useridentity.NamesakesUnknownError: taking the
// local account alone hid the twin (GAP-1131, GAP-1132).
func SameNameAccounts(ctx context.Context, r Resolver, account Account) ([]Account, error) {
	bare, _ := useridentity.SplitQualifiedName(account.Name)
	if r == nil || bare == "" {
		return nil, nil
	}
	candidates := []string{bare}
	realms, realmErr := sameNameRealms(ctx)
	if len(realms) > maxSameNameRealms {
		realms = realms[:maxSameNameRealms]
	}
	for _, realm := range realms {
		if realm.Domain != "" {
			candidates = append(candidates, bare+"@"+realm.Domain)
		}
		if realm.NetBIOS != "" {
			candidates = append(candidates, realm.NetBIOS+`\`+bare)
		}
	}
	seen := map[int]bool{account.UID: true}
	var twins []Account
	lookupErr := realmErr
	note := func(err error) {
		if lookupErr == nil {
			lookupErr = err
		}
	}
	add := func(found Account) {
		foundBare, _ := useridentity.SplitQualifiedName(found.Name)
		if seen[found.UID] || !useridentity.EqualFold(foundBare, bare) {
			return
		}
		seen[found.UID] = true
		twins = append(twins, found)
	}
	for _, candidate := range candidates {
		found, err := r.LookupUser(candidate)
		var mismatch *NameMismatchError
		if errors.As(err, &mismatch) {
			found, err = mismatch.Answered, nil
		}
		if err != nil {
			if !IsNotFound(err) {
				note(fmt.Errorf("look up %s: %w", candidate, err))
			}
			continue
		}
		add(found)
	}
	services, err := passwdProviders()
	if err != nil {
		note(err)
	}
	per, _ := r.(serviceResolver)
	for _, service := range services {
		if !validServiceName(service) {
			continue
		}
		found, lookup := Account{}, errNoServiceLookup
		if per != nil {
			found, lookup = per.LookupUserInService(service, bare)
		}
		switch {
		case lookup == nil:
			add(found)
		case errors.Is(lookup, errNoServiceLookup):
			if !nssLocalPasswdSources[service] {
				note(fmt.Errorf("look up %s in %s: %w", bare, service, lookup))
			}
		case IsNotFound(lookup):
			if answerErr := per.passwdServiceAnswers(service); answerErr != nil {
				note(fmt.Errorf("look up %s in %s: %w", bare, service, answerErr))
			}
		default:
			note(fmt.Errorf("look up %s in %s: %w", bare, service, lookup))
		}
	}
	if len(twins) == 0 && lookupErr != nil {
		return nil, &useridentity.NamesakesUnknownError{Name: bare, Err: lookupErr}
	}
	return twins, nil
}

// errNoJoinedDomain is the reason a bare name is refused when no source names
// every joined domain while a directory configuration may serve one.
var errNoJoinedDomain = errors.New("realmd lists no joined domain")

// errSSSDDomainsUnread is the reason a bare name is refused while SSSD
// serves accounts and its configuration cannot be read in full: sssd.conf is
// readable by root only, so an unprivileged reader (the managed gateway)
// cannot tell every domain SSSD serves, and with qualified names a bare
// lookup asks none of them.
var errSSSDDomainsUnread = errors.New("the SSSD configuration cannot be read in full (sssd.conf is readable by root only), " +
	"so not every domain SSSD serves is known")

// maxSameNameRealms bounds the domains a bare name is qualified with, one
// lookup each.
const maxSameNameRealms = 64

// sameNameRealms returns the domains SameNameAccounts qualifies a bare name
// with: the realms realmd lists now, those of fallbackRealms (the realms
// realmd last listed, the default realm of krb5.conf, the domains of the
// SSSD configuration), the trusted subdomains SSSD discovered
// (sssdSubdomains), the child domains ai_discovery.trusted_ad_child_domains
// lists, and the domains winbind serves (winbindDomains), so a domain one
// source does not name is still asked (review of GAP-1131). Its error says
// the list may miss a domain, whatever realmd lists: realmd names only the
// realms it joined, not a second domain an administrator configured. That
// is so while SSSD serves accounts (the sss module and an SSSD
// configuration) and its configuration cannot be read in full; while
// winbind serves accounts and cannot list the domains it trusts; and while
// an Entra ID module serves accounts and realmd neither lists a realm now
// nor listed one before. A host with the sss module but no SSSD
// configuration, the RHEL default, has no domain to miss.
func sameNameRealms(ctx context.Context) ([]Realm, error) {
	listed, realmErr := hostRealms(ctx)
	var realms []Realm
	add := func(realm Realm) {
		if slices.ContainsFunc(realms, func(known Realm) bool {
			return realm.Domain != "" && strings.EqualFold(known.Domain, realm.Domain) ||
				realm.Domain == "" && strings.EqualFold(known.NetBIOS, realm.NetBIOS)
		}) {
			return
		}
		realms = append(realms, realm)
	}
	for _, realm := range slices.Concat(listed, fallbackRealms()) {
		add(realm)
	}
	for _, domain := range slices.Concat(sssdSubdomains(), useridentity.TrustedADChildDomains()) {
		if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
			add(Realm{Domain: domain})
		}
	}
	if !nssConsultsDirectory() {
		return realms, nil
	}
	services, err := passwdProviders()
	if err != nil {
		return realms, err
	}
	var partial error
	if slices.Contains(services, "sss") && sssdConfigured() {
		if _, complete := sssdDomains(); !complete {
			partial = errSSSDDomainsUnread
		}
	}
	if slices.Contains(services, "winbind") {
		domains, err := winbindDomains(ctx)
		for _, netBIOS := range domains {
			add(Realm{NetBIOS: netBIOS})
		}
		if err != nil && partial == nil {
			partial = err
		}
	}
	known := realmErr == nil && len(listed) > 0 || len(lastListedRealms()) > 0
	if partial == nil && !known && slices.ContainsFunc(services, func(service string) bool { return entraIDServices[service] }) {
		partial = errNoJoinedDomain
		if realmErr != nil {
			partial = realmErr
		}
	}
	return realms, partial
}

var (
	krb5ConfPath = "/etc/krb5.conf"
	sssdConfPath = "/etc/sssd/sssd.conf"
	sssdConfDir  = "/etc/sssd/conf.d"
	// sssdPubconfKrb5Dir is where SSSD publishes, readable by any account,
	// the Kerberos domain_realm mappings of its domains and of the trusted
	// subdomains it discovers (domain_realm_<domain>), which no
	// configuration file names.
	sssdPubconfKrb5Dir = "/var/lib/sss/pubconf/krb5.include.d"
	// wbinfoPaths are where Samba installs wbinfo, which lists the domains
	// winbind trusts.
	wbinfoPaths = []string{"/usr/bin/wbinfo"}
)

// entraIDServices are the NSS passwd services of Entra ID, whose domains
// only realmd names here.
var entraIDServices = map[string]bool{"himmelblau": true, "aad": true}

// sssdSubdomains lists the DNS domains of SSSD's published domain_realm
// mappings (sssdPubconfKrb5Dir): its AD and IPA domains and the trusted
// subdomains it discovered. With qualified names SSSD names a subdomain's
// account name@subdomain, and a bare lookup reaches none of them.
func sssdSubdomains() []string {
	entries, err := os.ReadDir(sssdPubconfKrb5Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "domain_realm_") || !entry.Type().IsRegular() {
			continue
		}
		data, err := readSmallFile(filepath.Join(sssdPubconfKrb5Dir, entry.Name()), 1<<20)
		if err != nil {
			continue
		}
		section := ""
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
				continue
			}
			key, _, ok := strings.Cut(line, "=")
			domain := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(key), "."))
			if !ok || section != "domain_realm" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " \t@\\/") ||
				slices.Contains(out, domain) {
				continue
			}
			if out = append(out, domain); len(out) == maxSameNameRealms {
				return out
			}
		}
	}
	return out
}

// winbindDomains lists the NetBIOS names of the domains winbind serves: the
// workgroup of smb.conf and, unless smb.conf turns trusts off (allow trusted
// domains = no), the domains winbind lists (wbinfo -m). Without smb.conf
// winbind serves none. A list winbind cannot give is an error: the
// DOMAIN\name twin in a trusted domain would go unasked.
func winbindDomains(ctx context.Context) ([]string, error) {
	data, err := readSmallFile(sambaConfPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var domains []string
	if err == nil {
		if workgroup := strings.ToUpper(sambaGlobal(string(data), "workgroup")); validNetBIOSCandidate(workgroup) {
			domains = append(domains, workgroup)
		}
		switch strings.ToLower(sambaGlobal(string(data), "allow trusted domains")) {
		case "no", "false", "off", "0":
			if len(domains) > 0 {
				return domains, nil
			}
		}
	}
	listed, err := winbindTrustedDomains(ctx)
	if err != nil {
		return domains, fmt.Errorf("unixidentity: list the domains winbind serves (wbinfo -m): %w", err)
	}
	for _, domain := range listed {
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

// winbindTrustedDomains asks winbind which domains it serves (wbinfo -m):
// its own and the ones it trusts. Tests replace it.
var winbindTrustedDomains = func(ctx context.Context) ([]string, error) {
	path, err := firstTrustedTool(wbinfoPaths...)
	if err != nil {
		return nil, err
	}
	result, err := runTrustedCommand(ctx, path, []string{"-m"})
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("wbinfo -m exited %d", result.exitCode)
	}
	return parseWbinfoDomains(string(result.stdout)), nil
}

// parseWbinfoDomains reads the NetBIOS domain names of wbinfo -m output, one
// per line, without BUILTIN, which holds no user accounts.
func parseWbinfoDomains(output string) []string {
	var out []string
	for _, line := range strings.Split(output, "\n") {
		name := strings.ToUpper(strings.TrimSpace(line))
		if name == "BUILTIN" || !validNetBIOSCandidate(name) || slices.Contains(out, name) {
			continue
		}
		if out = append(out, name); len(out) == maxSameNameRealms {
			break
		}
	}
	return out
}

// sssdConfigured reports whether an SSSD configuration exists, readable or
// not: sssd.conf or a conf.d snippet. Without one SSSD serves no domain.
func sssdConfigured() bool {
	if _, err := os.Stat(sssdConfPath); !errors.Is(err, os.ErrNotExist) {
		return true
	}
	entries, err := os.ReadDir(sssdConfDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return true
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".conf") {
			return true
		}
	}
	return false
}

// fallbackRealms names the joined domains without realmd: the realms
// realmd last listed (lastListedRealms), the default realm of krb5.conf and
// the domains of the SSSD configuration (sssdDomains). The last two give a
// domain name only, so a bare name is qualified as name@domain.
func fallbackRealms() []Realm {
	out := lastListedRealms()
	add := func(domain string, dns bool) {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || dns && !strings.Contains(domain, ".") || strings.ContainsAny(domain, " \t@\\/") {
			return
		}
		for _, realm := range out {
			if strings.EqualFold(realm.Domain, domain) {
				return
			}
		}
		realm := Realm{Domain: domain}
		if strings.Contains(domain, ".") {
			realm.Name = strings.ToUpper(domain)
		}
		out = append(out, realm)
	}
	if data, err := readSmallFile(krb5ConfPath, 1<<20); err == nil {
		add(iniValue(string(data), "libdefaults", "default_realm"), true)
	}
	domains, _ := sssdDomains()
	for _, domain := range domains {
		add(domain, false)
	}
	return out
}

// sssdDomains lists the domains the SSSD configuration names: the domains
// option of [sssd] and each [domain/NAME] section, in sssd.conf and in the
// conf.d snippets SSSD merges into it. With qualified names SSSD names an
// account of domain NAME name@NAME, whether or not NAME is a DNS name
// ([domain/LDAP]). complete reports that every configuration file was read
// and they name a domain; sssd.conf is readable by root only.
func sssdDomains() (domains []string, complete bool) {
	paths := []string{sssdConfPath}
	entries, err := os.ReadDir(sssdConfDir)
	readable := err == nil || errors.Is(err, os.ErrNotExist)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".conf") {
			paths = append(paths, filepath.Join(sssdConfDir, entry.Name()))
		}
	}
	add := func(domain string) {
		domain = strings.TrimSpace(domain)
		if domain != "" && !slices.ContainsFunc(domains, func(known string) bool { return strings.EqualFold(known, domain) }) {
			domains = append(domains, domain)
		}
	}
	for _, path := range paths {
		data, err := readSmallFile(path, 1<<20)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			readable = false
			continue
		}
		for _, domain := range strings.Split(iniValue(string(data), "sssd", "domains"), ",") {
			add(domain)
		}
		for _, section := range iniSections(string(data)) {
			if len(section) > len("domain/") && strings.EqualFold(section[:len("domain/")], "domain/") {
				add(section[len("domain/"):])
			}
		}
	}
	return domains, readable && len(domains) > 0
}

// iniSections lists the section names of an INI-style file, as written.
func iniSections(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			out = append(out, strings.TrimSpace(line[1:len(line)-1]))
		}
	}
	return out
}

// iniValue returns the value of key in [section] of an INI-style file
// (krb5.conf, sssd.conf), or "".
func iniValue(content, section, key string) string {
	current := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if ok && current == section && strings.EqualFold(strings.TrimSpace(name), key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// nssConsultsDirectory reports whether the passwd line of nsswitch.conf
// names a directory service; true when the file cannot be read, as its
// answer is then unknown. Without the file glibc reads the local files.
func nssConsultsDirectory() bool {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	for _, service := range ParseNSSwitchServices(string(data), "passwd") {
		if _, ok := directoryServices[service]; ok {
			return true
		}
	}
	return false
}

// parseGroupName reads the name and gid of a group(5) line. Unlike
// ParseGroupLine it accepts the spaces directory group names carry ("domain
// users@corp.example.com"): the name is only reported, never used to
// resolve an account.
func parseGroupName(line string) (int, string, bool) {
	fields := strings.Split(strings.TrimRight(line, "\r\n"), ":")
	if len(fields) != 4 || fields[0] == "" || len(fields[0]) > maxNameLength {
		return 0, "", false
	}
	for _, r := range fields[0] {
		if r < 0x20 || r == 0x7f || r == ',' {
			return 0, "", false
		}
	}
	gid, err := parseID(fields[2], "gid")
	if err != nil {
		return 0, "", false
	}
	return gid, fields[0], true
}

// passwdProviders lists the services NSS asks for an account by name: the
// passwd line of nsswitch.conf as nssServicesInUse reads it, or glibc's
// default, files, without the file.
func passwdProviders() ([]string, error) {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return []string{"files"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unixidentity: read NSS configuration: %w", err)
	}
	return nssServicesInUse(string(data), "passwd", localPasswdPath), nil
}

// nssServicesInUse is ParseNSSwitchServices for database without the
// services compat includes while the local file of the database (localPath)
// has no + line: compat asks them only for such lines, so a Debian host with
// the default "group: compat" and no NIS does not wait on a NIS that is
// never asked.
func nssServicesInUse(content, database, localPath string) []string {
	services := ParseNSSwitchServices(content, database)
	if !slices.Contains(nssSwitchLine(content, database), "compat") || compatIncludes(localPath) {
		return services
	}
	var out []string
	for _, service := range nssSwitchLine(content, database) {
		if service == "compat" {
			service = "files"
		}
		if !slices.Contains(out, service) {
			out = append(out, service)
		}
	}
	return out
}

// compatIncludes reports whether a passwd(5) or group(5) file has a + line,
// one that includes accounts or groups of another service through compat. A
// file that cannot be read may have one.
func compatIncludes(path string) bool {
	data, err := readSmallFile(path, 16<<20)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "+") {
			return true
		}
	}
	return false
}

// errNoServiceLookup is a resolver that cannot ask one NSS service.
var errNoServiceLookup = errors.New("unixidentity: the account resolver cannot ask one NSS service")

// serviceResolver asks one NSS service for an account by name, and tells
// whether that service's "no such account" is definitive (NSSResolver, and
// a CachingResolver around one).
type serviceResolver interface {
	LookupUserInService(service, name string) (Account, error)
	passwdServiceAnswers(service string) error
}

// LookupUserInService asks the wrapped resolver's one NSS service; it is not
// cached, as only an administrator view asks.
func (c *CachingResolver) LookupUserInService(service, name string) (Account, error) {
	if inner, ok := c.inner.(serviceResolver); ok {
		return inner.LookupUserInService(service, name)
	}
	return Account{}, errNoServiceLookup
}

func (c *CachingResolver) passwdServiceAnswers(service string) error {
	if inner, ok := c.inner.(serviceResolver); ok {
		return inner.passwdServiceAnswers(service)
	}
	return errNoServiceLookup
}

// passwdServiceAnswers reports, with nil, that a "no such account" answer of
// service to a lookup by name is definitive: the service reads local files,
// the directory it reaches is not configured on this host (no SSSD
// configuration, no smb.conf), or it shows that it answers: SSSD's NSS
// responder and winbindd accept a connection, a member-list directory lists
// an entry (serviceAnswers). Any other service cannot show it.
func (r *NSSResolver) passwdServiceAnswers(service string) error {
	switch {
	case nssLocalPasswdSources[service]:
		return nil
	case service == "sss":
		if !sssdConfigured() {
			return nil
		}
		sssd, err := dialSSSDNSS(r.context())
		if err != nil {
			return fmt.Errorf("%w: %w", err, errDirectoryUnconfirmed)
		}
		sssd.Close()
		return nil
	case service == "winbind":
		if _, err := os.Stat(sambaConfPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return winbindAnswers(r.context())
	case memberListServices[service]:
		return r.serviceAnswers(service)
	}
	return fmt.Errorf("unixidentity: cannot tell whether NSS service %s answers: %w: %w", service, errServiceUncheckable, errDirectoryUnconfirmed)
}

// errServiceUncheckable marks an NSS service DefenseClaw has no way to see
// answer (passwdServiceAnswers).
var errServiceUncheckable = errors.New("DefenseClaw has no check for this NSS service")

// passwdOwner names the NSS passwd service that holds uid, asking the
// services of the passwd line in order as glibc does (passwdProviders), with
// its answer. A service's "no such account" passes the uid on only when the
// service shows that it answers (passwdServiceAnswers): getent reports an
// nslcd, ypbind, winbindd or SSSD that cannot answer the same way, and an
// account a later service still holds under the uid is then not proved to be
// the one the uid belongs to. A service DefenseClaw has no check for (an
// Entra ID module, another module) is taken at its word, as before.
// ErrNotFound when every service says no account holds it.
func (r *NSSResolver) passwdOwner(uid int) (string, Account, error) {
	services, err := passwdProviders()
	if err != nil {
		return "", Account{}, err
	}
	for _, service := range services {
		if !validServiceName(service) {
			continue
		}
		account, err := r.LookupUIDInService(service, uid)
		if err == nil {
			return service, account, nil
		}
		if !IsNotFound(err) {
			return "", Account{}, err
		}
		if err := r.passwdServiceAnswers(service); err != nil && !errors.Is(err, errServiceUncheckable) {
			return "", Account{}, fmt.Errorf("unixidentity: NSS service %s holds no uid %d but cannot show that it answers: %w", service, uid, err)
		}
	}
	return "", Account{}, ErrNotFound
}

// winbindPipes are the sockets winbindd serves the NSS module on, the
// current location first. Tests replace them.
var winbindPipes = []string{"/run/samba/winbindd/pipe", "/var/run/samba/winbindd/pipe"}

// winbindAnswers reports, with nil, that winbindd accepts a connection.
func winbindAnswers(ctx context.Context) error {
	errs := []error{errDirectoryUnconfirmed}
	for _, path := range winbindPipes {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", path)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		errs = append(errs, err)
	}
	return fmt.Errorf("unixidentity: winbindd does not answer: %w", errors.Join(errs...))
}

// AccountIncarnation names the account that holds uid, where its name, uid
// and home cannot: "files" for an account of /etc/passwd, and otherwise by
// the NSS service that answers the uid (passwdOwner): the SID SSSD holds for
// an SSSD account ("sid:S-1-5-..."), "sss" for one without a SID, and
// "nss:<service>" for an account of another service (nss:ldap, nss:nis,
// nss:winbind). Two accounts of one name, uid and home in two domains, one
// deleted and created again with another SID, or an SSSD account whose uid an
// LDAP account took over while SSSD still caches the first one's SID, differ
// in it, so the gateway does not serve the facts or the guardian record of
// one to the other (review of GAP-0551). known is false when it cannot tell:
// a service before the owner cannot show that it answers, the owner names
// another account than name, or SSSD does not answer.
func (r *NSSResolver) AccountIncarnation(uid int, name string) (string, bool) {
	local, err := LocalAccounts(r.context())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if localUID, ok := local[name]; ok && localUID == uid {
		return "files", true
	}
	service, owner, err := r.passwdOwner(uid)
	if err != nil || owner.Name != name {
		return "", false
	}
	if service != "sss" {
		return "nss:" + service, true
	}
	sssd, err := dialSSSDNSS(r.context())
	if err != nil {
		return "", false
	}
	defer sssd.Close()
	sid, err := sssdAccountSID(sssd, uid)
	if err != nil {
		return "", false
	}
	if sid != "" {
		return "sid:" + strings.ToUpper(sid), true
	}
	return "sss", true
}
