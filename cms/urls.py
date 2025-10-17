from django.urls import path
from .views import (
    health_check,
    register_user,
    CustomTokenObtainPairView,
    get_me,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('health/', health_check, name='health_check'),
    path('auth/register/',
         register_user,
         name='register_user'),
    path('auth/login/',
         CustomTokenObtainPairView.as_view(),
         name='custom_token_obtain_pair'
         ),
    path('token/refresh/',
         TokenRefreshView.as_view(),
         name='token_refresh'),
    path('auth/me/',
         get_me,
         name='get_me')
]
