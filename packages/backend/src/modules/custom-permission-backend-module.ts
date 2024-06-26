/**
 * @see https://backstage.io/docs/backend-system/building-backends/migrating#the-permission-plugin
 */
import { createBackendModule } from '@backstage/backend-plugin-api';

import { BackstageIdentityResponse } from '@backstage/plugin-auth-node';
import {
  catalogConditions,
  createCatalogConditionalDecision,
} from '@backstage/plugin-catalog-backend/alpha';
import {
  catalogEntityCreatePermission,
  catalogEntityDeletePermission,
} from '@backstage/plugin-catalog-common/alpha';
import {
  AuthorizeResult,
  PolicyDecision,
  isPermission,
} from '@backstage/plugin-permission-common';
import {
  PermissionPolicy,
  PolicyQuery,
} from '@backstage/plugin-permission-node';
import { policyExtensionPoint } from '@backstage/plugin-permission-node/alpha';

/**
 * @see https://backstage.io/docs/permissions/writing-a-policy
 */
class CustomPermissionPolicy implements PermissionPolicy {
  async handle(
    request: PolicyQuery,
    user?: BackstageIdentityResponse,
  ): Promise<PolicyDecision> {
    /**
     * Allows only resources that were created by the respective user to be deleted
     */
    if (isPermission(request.permission, catalogEntityDeletePermission)) {
      return createCatalogConditionalDecision(
        request.permission,
        catalogConditions.isEntityOwner({
          claims: user?.identity.ownershipEntityRefs ?? [],
        }),
      );
    }

    /**
     * Removes "Register Existing Component" button from /create and returns 404 on /catalog-import
     */
    if (request.permission.name === catalogEntityCreatePermission.name) {
      return {
        result: AuthorizeResult.DENY,
      };
    }

    return {
      result: AuthorizeResult.ALLOW,
    };
  }
}

export const CustomPermissionBackendModule = createBackendModule({
  pluginId: 'permission',
  moduleId: 'custom-policy',
  register(reg) {
    reg.registerInit({
      deps: { policy: policyExtensionPoint },
      async init({ policy }) {
        policy.setPolicy(new CustomPermissionPolicy());
      },
    });
  },
});
