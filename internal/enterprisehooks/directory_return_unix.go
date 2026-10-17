// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"net"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The return of a domain controller after an outage (macOS).
//
// While a bound Mac's domain controller does not answer, Open Directory fills
// its caches with answers that list an Active Directory account without its
// domain groups (its primary group, Domain Users, as a bare number). It keeps
// serving those answers for many minutes after the domain controller is back,
// so the accounts stayed on the default profile (default_lookup_failed) until
// an administrator flushed the caches by hand (#1197, GAP-0680, GAP-0517).
// Nothing in Open Directory's answers says the domain controller is back:
// `odutil show nodenames` lists the node Online through the outage, and the
// guardian's own lookups of a mobile account succeed from the local node, so
// a pass that "resolved accounts again" is no signal either (it fired during
// the outage, and never after it). The guardian therefore asks the domain
// controller itself, and only while Open Directory lists an enrolled Active
// Directory account without its groups: DirectoryCachesStale names the
// account's domain, DomainControllerAnswers says whether one of its domain
// controllers accepts a connection, and only then are the caches flushed
// (FlushDirectoryCaches). During the outage nothing is flushed, so the answers
// Open Directory still holds are kept.

// directoryLDAPPort is the port a domain controller's LDAP service listens on.
const directoryLDAPPort = "389"

// domainControllerDialTimeout bounds one connection attempt,
// domainControllerProbeTargets how many domain controllers are tried, and
// domainControllerProbeTimeout the whole probe, the SRV lookup included: a
// resolver that does not answer during the outage must not hold the
// guardian's 15 second poll for longer.
const (
	domainControllerDialTimeout  = 3 * time.Second
	domainControllerProbeTargets = 3
	domainControllerProbeTimeout = 10 * time.Second
)

// Tests replace the resolver and the dialer.
var (
	domainControllerSRV = func(ctx context.Context, domain string) ([]*net.SRV, error) {
		_, records, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
		return records, err
	}
	domainControllerDial = func(ctx context.Context, address string) error {
		conn, err := (&net.Dialer{Timeout: domainControllerDialTimeout}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
)

// DomainControllerAnswers reports whether a domain controller of the Active
// Directory domain (a DNS name, such as corp.example.com) accepts a
// connection on its LDAP port: the domain's SRV records name its domain
// controllers, and without them the domain's own name does. Nothing is sent
// over the connection.
func DomainControllerAnswers(ctx context.Context, domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDirectoryDomain(domain) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, domainControllerProbeTimeout)
	defer cancel()
	var hosts []string
	if records, err := domainControllerSRV(ctx, domain); err == nil {
		for _, record := range records {
			if host := strings.TrimSuffix(record.Target, "."); host != "" && len(hosts) < domainControllerProbeTargets {
				hosts = append(hosts, host)
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []string{domain}
	}
	for _, host := range hosts {
		if ctx.Err() != nil {
			return false
		}
		if domainControllerDial(ctx, net.JoinHostPort(host, directoryLDAPPort)) == nil {
			return true
		}
	}
	return false
}

// validDirectoryDomain accepts a DNS domain name of two or more labels.
func validDirectoryDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// DirectoryCachesStale reports whether the operating system's directory
// caches list an enrolled Active Directory account without its domain groups
// now, and the account's domain. Only a Mac answers so (a Linux host's SSSD
// refreshes what it served offline by itself); dir is the identity spool,
// whose records say which accounts are Active Directory ones.
func DirectoryCachesStale(dir string, accounts []IdentitySpoolAccount) (string, bool) {
	if !directoryCachesHoldOutageAnswers {
		return "", false
	}
	return directoryCachesStale(dir, accounts, accountGroupsListed)
}

// directoryCachesStale is DirectoryCachesStale with the account lookup
// listed, which reports whether the system names the account uid and its
// primary group.
func directoryCachesStale(dir string, accounts []IdentitySpoolAccount, listed func(uid int) bool) (string, bool) {
	for _, account := range accounts {
		if account.UID <= 0 {
			continue
		}
		record, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(account.UID), nil)
		if err != nil || record.Facts.Directory != useridentity.DirectoryActiveDirectory {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(record.Facts.Domain))
		if !validDirectoryDomain(domain) {
			continue
		}
		if !listed(account.UID) {
			return domain, true
		}
	}
	return "", false
}

// accountGroupsListed reports whether the system names the account uid and
// its primary group (an unnamed one is how Open Directory lists an Active
// Directory account it has no domain groups for).
func accountGroupsListed(uid int) bool {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false
	}
	group, err := user.LookupGroupId(account.Gid)
	return err == nil && group.Name != ""
}
