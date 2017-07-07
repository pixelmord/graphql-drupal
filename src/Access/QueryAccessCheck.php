<?php

namespace Drupal\graphql\Access;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Routing\Access\AccessInterface;
use Drupal\Core\Session\AccountInterface;
use Symfony\Component\HttpFoundation\Request;

class QueryAccessCheck implements AccessInterface {

  /**
   * Checks access.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The currently logged in account.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function access(Request $request, AccountInterface $account) {
    // Batched requests can be a mixture of persisted or unpersisted queries.
    // Since they are also getting access checked on each individual subrequest
    // we will let the request through if one of the two permissions have been
    // granted.
    if ($request->attributes->get('type') === 'batch') {
      return AccessResult::allowedIfHasPermissions($account, ['execute graphql requests', 'execute persisted graphql requests'], 'OR');
    }

    // Arbitrary queries may only be executed if the user has the global
    // 'execute graphql requests' permission.
    if (!$request->attributes->get('persisted', FALSE)) {
      return AccessResult::allowedIfHasPermission($account, 'execute graphql requests');
    }

    // This is a persisted query, grant access if the user has the global
    // 'execute graphql requests' permission or the more specific one for
    // persisted queries.
    return AccessResult::allowedIfHasPermissions($account, ['execute graphql requests', 'execute persisted graphql requests'], 'OR');
  }

}
