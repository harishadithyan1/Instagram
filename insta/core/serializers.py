from rest_framework import serializers
from .models import RegisterUser,Posts
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model

class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = RegisterUser
        fields = ['email', 'full_name', 'user_name', 'password', 'confirm_password','profile']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def validate_email(self, value):
        if RegisterUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_user_name(self, value):
        if RegisterUser.objects.filter(user_name=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        validated_data['password'] = make_password(validated_data['password'])
        return RegisterUser.objects.create(**validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            try:
                user = RegisterUser.objects.get(user_name=username)
                if user.check_password(password):
                    data['user'] = user
                    return data
                raise serializers.ValidationError("Incorrect password")
            except RegisterUser.DoesNotExist:
                raise serializers.ValidationError("User does not exist")
        else:
            raise serializers.ValidationError("Must include username and password")

class EmailSerializer(serializers.Serializer):
    email=serializers.CharField(write_only=True)
    def validate(self, attrs):
        email=attrs.get('email')
        if not email:
            raise serializers.ValidationError({"Check the Email"})
        return attrs
    
class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)


class OtpSerializer(serializers.Serializer):
    otp = serializers.CharField(write_only=True)

class PostsSerializer(serializers.ModelSerializer):
    media = serializers.ImageField(required=False)  # Works for both images/videos

    class Meta:
        model = Posts
        fields = ['id', 'user', 'media', 'caption', 'created_at']
        read_only_fields = ['id', 'created_at', 'user']

    def create(self, validated_data):
        return Posts.objects.create(**validated_data)



class SimpleUserSerializer(serializers.ModelSerializer):
    profile = serializers.ImageField(required=False)
    class Meta:
        model = RegisterUser
        fields = ['user_name', 'full_name', 'profile']
    def get_profile(self, obj):
        if obj.profile:
            return self.context['request'].build_absolute_uri(obj.profile.url)
        return None  
    def create(self, validated_data):
        return Posts.objects.create(**validated_data)

from .models import Message

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.SerializerMethodField()
    recipient = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = ['id', 'sender', 'recipient', 'content', 'timestamp']

    def get_sender(self, obj):
        return obj.sender.user_name if obj.sender else None

    def get_recipient(self, obj):
        return obj.recipient.user_name if obj.recipient else None


from rest_framework import serializers
from .models import Story
from .models import RegisterUser  # adjust based on your user model location

class StorySerializer(serializers.ModelSerializer):
    user = SimpleUserSerializer(read_only=True)
    media = serializers.SerializerMethodField()
    is_liked = serializers.SerializerMethodField()

    class Meta:
        model = Story
        fields = ['id', 'media', 'created_at', 'user', 'is_liked']
        read_only_fields = ['id', 'created_at', 'user']

    def get_media(self, obj):
        request = self.context.get('request')
        return request.build_absolute_uri(obj.media.url) if obj.media else None

    def get_is_liked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.likes.filter(id=request.user.id).exists()
        return False
