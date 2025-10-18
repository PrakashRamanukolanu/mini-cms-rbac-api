from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import (
    IsAuthenticated,
    IsAuthenticatedOrReadOnly,
    AllowAny,
)
from .permissions_utils import user_has_perm, user_role_names
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import (
    UserRegistrationSerializer,
    CustomTokenObtainPairSerializer,
    PostSerializer,
    PostCreateSerializer,
    PageSerializer,
)
from .models import Post, Role, Page
from django.utils.text import slugify
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User


@api_view(['GET'])
def health_check(request):
    return Response({"status": "ok"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def register_user(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {"message": "User registered successfully"},
            status=status.HTTP_201_CREATED
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_me(request):
    user = request.user
    data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "roles": [role.name for role in user.roles.all()]
    }
    return Response(data, status=status.HTTP_200_OK)


def has_permission(user, perm_key):
    user_perms = set()
    for role in user.roles.all():
        user_perms.update(role.permissions.values_list('key', flat=True))
    return perm_key in user_perms


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def assign_role_to_user(request, user_id):
    # Check admin.rbac.manage permission
    if not has_permission(request.user, 'admin.rbac.manage'):
        return Response(
            {"detail": "Permission denied"},
            status=status.HTTP_403_FORBIDDEN)

    # Get target user
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {"detail": "User not found"},
            status=status.HTTP_404_NOT_FOUND)

    # Validate role_key
    role_key = request.data.get('role_key')
    if not role_key:
        return Response(
            {"detail": "role_key is required"},
            status=status.HTTP_400_BAD_REQUEST)

    try:
        role = Role.objects.get(name=role_key)
    except Role.DoesNotExist:
        return Response(
            {"detail": "Role not found"},
            status=status.HTTP_400_BAD_REQUEST)

    # Assign role to user (upsert)
    target_user.roles.add(role)
    target_user.save()

    return Response(
        {"detail":
         f"Role '{role_key}' assigned to user '{target_user.username}'"},
        status=status.HTTP_201_CREATED
    )


class PostViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def list(self, request):
        qs = Post.objects.filter(is_deleted=False)
        user = request.user if request.user.is_authenticated else None

        if not user:
            qs = qs.filter(status='published')
        else:
            if user_has_perm(user, 'content.view'):
                roles = user_role_names(user)
                if 'author' in roles:
                    qs = qs.filter(
                        models.Q(status='published') |
                        models.Q(author=user)
                        )
                # Editors/Reviewers/Admin can filter any status
                # add filtering by query params
                status_filter = request.query_params.get('status')
                author_filter = request.query_params.get('author_id')
                if status_filter:
                    qs = qs.filter(status=status_filter)
                if author_filter:
                    qs = qs.filter(author_id=author_filter)
            else:
                qs = qs.filter(status='published')

        serializer = PostSerializer(qs, many=True)
        return Response(serializer.data)

    def create(self, request):
        if not user_has_perm(request.user, 'content.create'):
            return Response(
                {'detail': 'Forbidden'},
                status=status.HTTP_403_FORBIDDEN)
        serializer = PostCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        slug = slugify(serializer.validated_data['title'])
        # ensure unique slug
        counter = 1
        base_slug = slug
        while Post.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        post = Post.objects.create(
            title=serializer.validated_data['title'],
            body=serializer.validated_data['body'],
            author=request.user,
            slug=slug,
            status='draft'
        )
        return Response(
            PostSerializer(post).data,
            status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        try:
            post = Post.objects.get(pk=pk, is_deleted=False)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        user = request.user if request.user.is_authenticated else None
        if not user and post.status != 'published':
            return Response(status=status.HTTP_404_NOT_FOUND)
        elif user:
            if not user_has_perm(user, 'content.view'):
                if post.status != 'published':
                    return Response(status=status.HTTP_404_NOT_FOUND)
            roles = user_role_names(user)
            if 'author' in roles and \
                post.author != user and \
                    post.status != 'published':
                return Response(status=status.HTTP_404_NOT_FOUND)

        return Response(PostSerializer(post).data)

    def partial_update(self, request, pk=None):
        """PATCH /posts/{id}"""
        try:
            post = Post.objects.get(pk=pk, is_deleted=False)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if not user_has_perm(request.user, 'content.update'):
            return Response(
                {'detail': 'Forbidden'},
                status=status.HTTP_403_FORBIDDEN)

        roles = user_role_names(request.user)
        if 'author' in roles \
            and post.author != request.user \
                or post.status != 'draft':
            return Response(
                {'detail': 'Authors can only update their own drafts'},
                status=status.HTTP_403_FORBIDDEN)

        serializer = PostCreateSerializer(
            post,
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(PostSerializer(post).data)

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        """POST /posts/{id}/submit"""
        try:
            post = Post.objects.get(pk=pk, is_deleted=False)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        roles = user_role_names(request.user)
        if 'author' in roles and post.author != request.user:
            return Response(
                {'detail': 'Forbidden'},
                status=status.HTTP_403_FORBIDDEN)

        if post.status == 'draft':
            post.status = 'in_review'
            post.save()
            return Response(
                {'detail': 'Submitted for review'},
                status=status.HTTP_200_OK)
        return Response(
            {'detail': 'Invalid status'},
            status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """POST /posts/{id}/publish"""
        try:
            post = Post.objects.get(pk=pk, is_deleted=False)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if not user_has_perm(request.user, 'content.publish'):
            return Response(
                {'detail': 'Forbidden'},
                status=status.HTTP_403_FORBIDDEN)

        roles = user_role_names(request.user)
        if post.status == 'in_review' or \
                ('editor' in roles or 'admin' in roles):
            post.status = 'published'
            post.published_at = timezone.now()
            post.save()
            return Response(
                {'detail': 'Published successfully'},
                status=status.HTTP_200_OK)

        return Response(
            {'detail': 'Cannot publish from current status'},
            status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def request_changes(self, request, pk=None):
        """POST /posts/{id}/request_changes"""
        try:
            post = Post.objects.get(pk=pk, is_deleted=False)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if not user_has_perm(request.user, 'content.review'):
            return Response(
                {'detail': 'Forbidden'},
                status=status.HTTP_403_FORBIDDEN)

        if post.status == 'in_review':
            post.status = 'draft'
            post.save()
            return Response(
                {'detail': 'Changes requested'},
                status=status.HTTP_200_OK)

        return Response(
            {'detail': 'Invalid status'},
            status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """DELETE /posts/{id}"""
        try:
            post = Post.objects.get(pk=pk, is_deleted=False)
        except Post.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if not user_has_perm(request.user, 'content.delete'):
            return Response(
                {'detail': 'Forbidden'},
                status=status.HTTP_403_FORBIDDEN)

        roles = user_role_names(request.user)
        if 'author' in roles and \
            post.author != request.user or \
                post.status != 'draft':
            return Response(
                {'detail': 'Authors can only delete their own drafts'},
                status=status.HTTP_403_FORBIDDEN)

        post.is_deleted = True
        post.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PageViewSet(viewsets.ModelViewSet):
    queryset = Page.objects.filter(is_deleted=False)
    serializer_class = PageSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]  # public can view published pages
        return [IsAuthenticated()]

    def get_queryset(self):
        user = self.request.user \
            if self.request.user.is_authenticated else None
        qs = Page.objects.filter(is_deleted=False)
        if not user:
            return qs.filter(status='published')

        roles = [r.name for r in user.roles.all()]
        if 'author' in roles:
            return qs.filter(
                models.Q(status='published') | models.Q(author=user))
        elif any(r in roles for r in ['editor', 'reviewer', 'admin']):
            return qs  # all pages visible
        else:
            return qs.filter(status='published')

    def perform_create(self, serializer):
        title = serializer.validated_data['title']
        slug = slugify(title)
        # ensure unique slug
        count = Page.objects.filter(slug__startswith=slug).count()
        if count:
            slug = f"{slug}-{count+1}"
        serializer.save(author=self.request.user, slug=slug, status='draft')
