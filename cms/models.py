from django.db import models
from django.contrib.auth.models import User


class Permission(models.Model):
    key = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.key


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    permissions = models.ManyToManyField(
        Permission,
        related_name='roles',
        blank=True)
    users = models.ManyToManyField(User, related_name='roles', blank=True)

    def __str__(self):
        return self.name


STATUS_CHOICES = [
    ('draft', 'Draft'),
    ('in_review', 'In Review'),
    ('published', 'Published'),
]

OBJECT_TYPE_CHOICES = [
    ('post', 'Post'),
    ('page', 'Page'),
]


class Post(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    body = models.TextField()
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='draft')
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='posts')
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['author']),
        ]


class Page(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    body = models.TextField()
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='draft')
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='pages')
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['author']),
        ]


class Comment(models.Model):
    object_type = models.CharField(max_length=10, choices=OBJECT_TYPE_CHOICES)
    object_id = models.PositiveIntegerField()
    author_name = models.CharField(max_length=255)
    author_email = models.EmailField()
    body = models.TextField()
    is_approved = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
