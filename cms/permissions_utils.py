def user_has_perm(user, perm_key):
    return user.roles.filter(permissions__key=perm_key).exists()


def user_role_names(user):
    return list(user.roles.values_list('name', flat=True))
