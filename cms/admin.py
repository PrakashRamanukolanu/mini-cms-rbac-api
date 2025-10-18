from django.contrib import admin
from .models import Role, Permission


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'key', 'description')
    search_fields = ('key',)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    filter_horizontal = ('permissions', 'users')
