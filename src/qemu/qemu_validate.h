/*
 * qemu_validate.h: QEMU general validation functions
 *
 * Copyright IBM Corp, 2020
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <glib-object.h>

#include "domain_conf.h"
#include "qemu_capabilities.h"

int qemuValidateDomainDef(const virDomainDef *def, void *opaque);
int qemuValidateDomainDeviceDefAddress(const virDomainDeviceDef *dev,
                                       virQEMUCapsPtr qemuCaps);
int qemuValidateDomainDeviceDefNetwork(const virDomainNetDef *net,
                                       virQEMUCapsPtr qemuCaps);
int qemuValidateDomainChrDef(const virDomainChrDef *dev,
                             const virDomainDef *def,
                             virQEMUCapsPtr qemuCaps);
int qemuValidateDomainSmartcardDef(const virDomainSmartcardDef *def,
                                   virQEMUCapsPtr qemuCaps);
int qemuValidateDomainRNGDef(const virDomainRNGDef *def,
                             virQEMUCapsPtr qemuCaps);
int qemuValidateDomainRedirdevDef(const virDomainRedirdevDef *def,
                                  virQEMUCapsPtr qemuCaps);
int qemuValidateDomainWatchdogDef(const virDomainWatchdogDef *dev,
                                  const virDomainDef *def);
