from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    health_check,
    register_user,
    CustomTokenObtainPairView,
    get_me,
    assign_role_to_user,
    PostViewSet,
    PageViewSet,
)
from rest_framework_simplejwt.views import TokenRefreshView

# DRF router for posts
router = DefaultRouter()
router.register(r'posts', PostViewSet, basename='post')

page_list = PageViewSet.as_view({
    'get': 'list',
    'post': 'create'
})

page_detail = PageViewSet.as_view({
    'get': 'retrieve',
    'patch': 'partial_update',
    'delete': 'destroy'
})

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
         name='get_me'),
    path('rbac/users/<int:user_id>/roles/',
         assign_role_to_user,
         name='assign_role_to_user'),

    path('', include(router.urls)),

    path('pages/', page_list, name='page-list'),
    path('pages/<int:pk>/', page_detail, name='page-detail'),
]
