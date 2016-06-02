<?php

/*
 * This file is part of the Sonata Project package.
 *
 * (c) Thomas Rabaix <thomas.rabaix@sonata-project.org>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sonata\UserBundle\Security;

use Sonata\AdminBundle\Admin\Pool;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class EditableRolesBuilder
{
    /**
     * @var SecurityContextInterface
     */
    protected $securityContextToken;

    /**
     * @var SecurityContextInterface
     */
    protected $securityContextAuthorizationChecker;

    /**
     * @var Pool
     */
    protected $pool;

    /**
     * @var array
     */
    protected $rolesHierarchy;

    /**
     * @param TokenStorageInterface $securityContextToken
     * @param AuthorizationCheckerInterface $securityContextAuthorizationChecker
     * @param Pool                     $pool
     * @param array                    $rolesHierarchy
     */
    public function __construct(TokenStorageInterface $securityContextToken, AuthorizationCheckerInterface $securityContextAuthorizationChecker, Pool $pool, array $rolesHierarchy = array())
    {
        $this->securityContextToken = $securityContextToken;
        $this->securityContextAuthorizationChecker = $securityContextAuthorizationChecker;
        $this->pool = $pool;
        $this->rolesHierarchy = $rolesHierarchy;
    }

    /**
     * @return array
     */
    public function getRoles()
    {
        $roles = array();
        $rolesReadOnly = array();

        if (!$this->securityContextToken->getToken()) {
            return array($roles, $rolesReadOnly);
        }

        // get roles from the Admin classes
        foreach ($this->pool->getAdminServiceIds() as $id) {
            try {
                $admin = $this->pool->getInstance($id);
            } catch (\Exception $e) {
                continue;
            }

            $isMaster = $admin->isGranted('MASTER');
            $securityHandler = $admin->getSecurityHandler();
            // TODO get the base role from the admin or security handler
            $baseRole = $securityHandler->getBaseRole($admin);

            if (strlen($baseRole) == 0) { // the security handler related to the admin does not provide a valid string
                continue;
            }

            foreach ($admin->getSecurityInformation() as $role => $permissions) {
                $role = sprintf($baseRole, $role);

                if ($isMaster) {
                    // if the user has the MASTER permission, allow to grant access the admin roles to other users
                    $roles[$role] = $role;
                } elseif ($this->securityContextAuthorizationChecker->isGranted($role)) {
                    // although the user has no MASTER permission, allow the currently logged in user to view the role
                    $rolesReadOnly[$role] = $role;
                }
            }
        }

        $isMaster = $this->securityContextAuthorizationChecker->isGranted('ROLE_SUPER_ADMIN');

        // get roles from the service container
        foreach ($this->rolesHierarchy as $name => $rolesHierarchy) {
            if ($this->securityContextAuthorizationChecker->isGranted($name) || $isMaster) {
                $roles[$name] = $name.': '.implode(', ', $rolesHierarchy);

                foreach ($rolesHierarchy as $role) {
                    if (!isset($roles[$role])) {
                        $roles[$role] = $role;
                    }
                }
            }
        }

        return array($roles, $rolesReadOnly);
    }
}
