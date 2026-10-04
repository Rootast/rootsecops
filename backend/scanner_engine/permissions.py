from rest_framework.permissions import BasePermission


class IsAdminOrSecurityManager(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and (user.is_staff or user.is_superuser or user.groups.filter(name__in=["admin", "security-admin"]).exists())
        )
