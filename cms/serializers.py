from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Role, Post, Page, Comment
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email'),
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )

        # Assign default role 'reader'
        reader_role = Role.objects.get(name='reader')
        reader_role.users.add(user)

        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # You can add custom claims if needed
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data['username'] = self.user.username
        data['email'] = self.user.email
        data['first_name'] = self.user.first_name
        data['last_name'] = self.user.last_name
        data['roles'] = [role.name for role in self.user.roles.all()]
        return data


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug',
            'body', 'status', 'author',
            'published_at', 'created_at', 'updated_at']
        read_only_fields = [
            'id', 'slug', 'author',
            'status', 'published_at',
            'created_at', 'updated_at']


class PostCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ['title', 'body']


class PageSerializer(serializers.ModelSerializer):
    author_id = serializers.ReadOnlyField(source='author.id')
    slug = serializers.ReadOnlyField()

    class Meta:
        model = Page
        fields = ['id', 'title', 'slug', 'body', 'status', 'author_id',
                  'published_at', 'created_at', 'updated_at', 'is_deleted']


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = [
            'id', 'object_type', 'object_id', 'author_name', 'author_email',
            'body', 'is_approved', 'is_deleted', 'created_at'
        ]
        read_only_fields = ['is_approved', 'is_deleted', 'created_at']
