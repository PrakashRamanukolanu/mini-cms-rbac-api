from django.urls import path
from .views import health_check, register_user
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    )


urlpatterns = [
    path('health/', health_check, name='health_check'),
    path('auth/register/', register_user, name='register_user'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
