from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from cloudinary.models import CloudinaryField
from django.contrib.auth import get_user_model
from django.forms import ValidationError
class RegisterUserManager(BaseUserManager):
    def create_user(self, email, full_name, user_name, password=None):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            email=self.normalize_email(email),
            full_name=full_name,
            user_name=user_name,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, user_name, password=None):
        """
        Creates and saves a superuser with the given email, name, username and password.
        """
        user = self.create_user(
            email=email,
            full_name=full_name,
            user_name=user_name,
            password=password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class RegisterUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, max_length=50)
    full_name = models.CharField(max_length=50)
    user_name = models.CharField(unique=True, max_length=50)
    profile=CloudinaryField('image',null=True)
    password = models.CharField(max_length=128)
    posts_no = models.IntegerField(default=0, null=True, blank=True)
    email_otp = models.CharField(max_length=10, blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_online = models.BooleanField(default=False) 
    objects = RegisterUserManager()
    
    USERNAME_FIELD = 'user_name'
    REQUIRED_FIELDS = ['email', 'full_name']

    def __str__(self):
        return self.user_name

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin
    


class Posts(models.Model):
    user = models.ForeignKey(RegisterUser, on_delete=models.CASCADE, related_name='posts')
    media = CloudinaryField('media', resource_type='auto')
    caption = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.user_name} - {self.caption}'
    
class Follow(models.Model):
    follower = models.ForeignKey(RegisterUser, related_name='following', on_delete=models.CASCADE)
    following = models.ForeignKey(RegisterUser, related_name='followers', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('follower', 'following')

    def __str__(self):
        return f"{self.follower.user_name} → {self.following.user_name}"

User = get_user_model()

from django.db import models
from django.conf import settings

class Message(models.Model):
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='sent_messages',
        on_delete=models.CASCADE
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='received_messages',
        on_delete=models.CASCADE
    )
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"{self.sender} to {self.recipient} at {self.timestamp}"


from django.db import models
from django.utils import timezone
from django.conf import settings
from cloudinary.models import CloudinaryField
from django.core.exceptions import ValidationError

class Story(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='stories')
    media = CloudinaryField('media', resource_type='auto')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    likes = models.ManyToManyField(User, related_name='liked_stories', blank=True)

    def liked_by(self):
        return [user.user_name for user in self.likes.all()]
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_active(self):
        return self.expires_at > timezone.now()

    def clean(self):
    # change self.image to self.media
        if not self.media:
           raise ValidationError("Media is required for story.")


    def __str__(self):
        return f"Story by {self.user.user_name}"

