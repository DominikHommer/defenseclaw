/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */


/* Linux HAL checks. */

#include "platform.h"
#include <assert.h>
#include <stdio.h>

/* Regression: the production prefix check compared 20 of the 21 characters
 * of "/var/lib/defenseclaw/", so "/var/lib/defenseclawX/flash.bin" passed. */
static void test_flash_path_prefix(void) {
    assert(hal_flash_path_is_provisioned("/var/lib/defenseclaw/flash.bin"));
    assert(hal_flash_path_is_provisioned("/etc/defenseclaw/flash.bin"));
    assert(!hal_flash_path_is_provisioned("/var/lib/defenseclawX/flash.bin"));
    assert(!hal_flash_path_is_provisioned("/var/lib/defenseclaw"));
    assert(!hal_flash_path_is_provisioned("/etc/defenseclawX/flash.bin"));
    assert(!hal_flash_path_is_provisioned("/tmp/flash.bin"));
    assert(!hal_flash_path_is_provisioned(NULL));
    printf("  PASS: production flash path prefix is matched exactly\n");
}

int main(void) {
    printf("test_hal_linux:\n");
    test_flash_path_prefix();
    return 0;
}
