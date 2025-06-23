from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view,permission_classes,parser_classes
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterSerializer,LoginSerializer,EmailSerializer,ChangePasswordSerializer,OtpSerializer, PostsSerializer
from .models import RegisterUser,Posts,Follow
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.core.mail import EmailMessage
from django.contrib import messages
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from .utils import generate_otp
from rest_framework import permissions, response, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
@api_view(['POST'])
def register_user(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        email_otp = generate_otp()
        user.email_otp = email_otp
        user.save()
        email_message = EmailMessage(
            subject=f'Registration successful - OTP for {user.full_name}',
            body=f'Your OTP for verification is: {email_otp}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email_message.send()

        return Response({
            "message": "User registered successfully. Check your email for OTP.",
            "user_id": user.id,
            "id": user.id
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# views.py
@api_view(['POST'])

def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            user = RegisterUser.objects.get(user_name=username)
        except RegisterUser.DoesNotExist:
            return Response({'error': 'Invalid username'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return Response({ 
                'message': 'Login successful!', 
                'user_id': user.id,
                'username': user.user_name,
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                }
            },status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid password'},status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])

def refresh_token_view(request):
    refresh = request.data.get('refresh')
    if refresh is None:
        return Response({'error': 'Refresh token is missing'}, status=400)
    try:
        refresh = RefreshToken(refresh)
        new_access = refresh.access_token
        return Response({'access': str(new_access)})
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['POST'])
def verify_email(request):
    serializer = EmailSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        user = RegisterUser.objects.filter(email=email).first()
        
        if user:
            user_id = user.id
            reset_link = f"http://127.0.0.1:3000/reset/{user_id}/" 
            email_message = EmailMessage(
                subject='Reset Your Password',
                body=f'Click the link to reset your password: {reset_link}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[email],
            )
            try:
                email_message.send()
                return Response({"message": "Email sent successfully","id": user.id}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({"error": "No user with this email"}, status=status.HTTP_404_NOT_FOUND)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def change_password(request, user_id):
    try:
        user = RegisterUser.objects.get(id=user_id)
    except RegisterUser.DoesNotExist:
        return Response({"error": "User not found"}, status=404)

    serializer = ChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        password=serializer.validated_data['password']
        confirm_password=serializer.validated_data['confirm_password']
        if password == confirm_password:
            user.password=make_password(password)
            user.save()
        return Response({"detail": "Password changed successfully."}, status=200)
    return Response(serializer.errors, status=400)

@api_view(['POST'])
def verify_otp(request, user_id):
    try:
        user = RegisterUser.objects.get(id=user_id)
    except RegisterUser.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    serializer = OtpSerializer(data=request.data)
    if serializer.is_valid():
        otp = serializer.validated_data['otp']

        if otp == user.email_otp:
            user.is_email_verified = True
            user.email_otp = None
            user.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])

@permission_classes([IsAuthenticated]) 
def logout_view(request):
    request.auth.delete()
    return Response({"msg": "User successfully logged out"},status=status.HTTP_200_OK)

from rest_framework.parsers import MultiPartParser, FormParser

@api_view(['GET', 'POST'])
@permission_classes([permissions.IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def profile_view(request):
    user = request.user

    if request.method == 'POST':
        if 'profile' in request.FILES:
            user.profile = request.FILES['profile']
            user.save()
            return Response(
                {
                    'message': 'Profile picture updated successfully.',
                    'profile_pic': user.profile.url
                },
                status=status.HTTP_200_OK
            )
        return Response({'error': 'No profile image provided.'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(
        {
            'username': user.user_name,
            'email': user.email,
            'full_name': user.full_name,
            'posts_no': user.posts_no,
            'profile_pic': user.profile.url if user.profile else None,
            'followers': user.followers.count(),     
            'following': user.following.count(),     
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET', 'POST'])
@permission_classes([permissions.IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def posts_view(request):
    if request.method == 'GET':
        posts = Posts.objects.filter(user=request.user)
        serializer = PostsSerializer(posts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'POST':
        serializer = PostsSerializer(data=request.data)
        if serializer.is_valid():
            post = serializer.save(user=request.user)
            # Correctly count posts and update user
            request.user.posts_no = Posts.objects.filter(user=request.user).count()
            request.user.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['PATCH'])
@permission_classes([permissions.IsAuthenticated])
def update_posts_no(request):
    user = request.user
    posts_no = request.data.get('posts_no')

    if posts_no is not None:
        user.posts_no = posts_no
        user.save()
        return Response({'message': 'Post count updated'}, status=200)
    else:
        return Response({'error': 'posts_no not provided'}, status=400)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def home(request):
    all_posts = Posts.objects.select_related('user').all()

    posts_data = []
    for post in all_posts:
        posts_data.append({
            "media": request.build_absolute_uri(post.media.url) if post.media else None,
            "posted_by": post.user.user_name,
            "profile": request.build_absolute_uri(post.user.profile.url) if post.user.profile else None
        })

    return Response({
        "username": request.user.user_name,
        "email": request.user.email,
        "full_name": request.user.full_name,
        "profile": request.build_absolute_uri(request.user.profile.url) if request.user.profile else None, 
        "posts": posts_data,
    }, status=status.HTTP_200_OK)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import RegisterUser, Posts, Follow

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_friend(request):
    user_name = request.query_params.get('user_name')
    if not user_name:
        return Response({"error": "user_name parameter is required."}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        friend = RegisterUser.objects.get(user_name=user_name)
    except RegisterUser.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    # ✅ Get posts created by this user
    friend_posts = Posts.objects.filter(user=friend).order_by('-created_at')  # optional ordering
    posts_data = []
    for post in friend_posts:
        posts_data.append({
            "media": request.build_absolute_uri(post.media.url) if post.media else None,
            "posted_by": friend.user_name,
            "profile": request.build_absolute_uri(friend.profile.url) if friend.profile else None,
        })

    is_owner = (friend == request.user)
    is_following = Follow.objects.filter(follower=request.user, following=friend).exists() if not is_owner else False

    return Response({
        "username": friend.user_name,
        "email": friend.email,
        "full_name": friend.full_name,
        "profile_pic": request.build_absolute_uri(friend.profile.url) if friend.profile else None,
        "posts_no": friend_posts.count(),
        "followers": friend.followers.count(),
        "following": friend.following.count(),
        "is_owner": is_owner,
        "is_following": is_following,
        "posts": posts_data
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def follow_user(request, username):
    try:
        target = RegisterUser.objects.get(user_name=username)
        user = request.user

        if user == target:
            return Response({'error': 'Cannot follow yourself'}, status=400)

        follow, created = Follow.objects.get_or_create(follower=user, following=target)
        if not created:
            follow.delete()
            return Response({
                'status': 'unfollowed',
                'followers_count': target.followers.count()
            })
        return Response({
            'status': 'followed',
            'followers_count': target.followers.count()
        })
    except RegisterUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)



@api_view(['GET'])
def get_follow_counts(request, username):
    try:
        user = RegisterUser.objects.get(user_name=username)
        followers_count = user.followers.count()
        following_count = user.following.count()
        return Response({
            "followers": followers_count,
            "following": following_count
        })
    except RegisterUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

@api_view(['GET'])
def get_followers_list(request, username):
    try:
        user = RegisterUser.objects.get(user_name=username)
        followers = user.followers.all().values('user_name', 'full_name')
        return Response({'followers': list(followers)})
    except RegisterUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)


@api_view(['GET'])
def get_following_list(request, username):
    try:
        user = RegisterUser.objects.get(user_name=username)
        following = user.following.all().values('user_name', 'full_name')
        return Response({'following': list(following)})
    except RegisterUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)


from .serializers import SimpleUserSerializer


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def followers_following_view(request):
    user = request.user
    follower_users = [follow.follower for follow in Follow.objects.filter(following=user)]
    following_users = [follow.following for follow in Follow.objects.filter(follower=user)]
    follower_serializer = SimpleUserSerializer(follower_users, many=True).data
    following_serializer = SimpleUserSerializer(following_users, many=True).data
    return Response({
        'followers': follower_serializer,
        'following': following_serializer,
        'user_name':user.user_name,
    })
# views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .models import Message
from .serializers import MessageSerializer
import re

User = get_user_model()

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_message(request):
    sender = request.user
    recipient_username = request.data.get('recipient')
    content = request.data.get('message')

    if not recipient_username or not content:
        return Response({"error": "Missing recipient or message content."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        recipient = User.objects.get(user_name=recipient_username)
    except User.DoesNotExist:
        return Response({"error": "Recipient user not found."}, status=status.HTTP_404_NOT_FOUND)

    message = Message.objects.create(sender=sender, recipient=recipient, content=content)
    serializer = MessageSerializer(message)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Message, RegisterUser as User  # Update this import as needed
from .serializers import MessageSerializer
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_messages(request, room_name):
    try:
        other_user = RegisterUser.objects.get(user_name=room_name)
    except RegisterUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=400)

    sent = Message.objects.filter(sender=request.user, recipient=other_user)
    received = Message.objects.filter(sender=other_user, recipient=request.user)

    sent_data = MessageSerializer(sent, many=True).data
    received_data = MessageSerializer(received, many=True).data

    return Response({
        'sent': sent_data,
        'received': received_data,
        'online': other_user.is_online  # ✅ Must be here and is_online must exist
    })


from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from .models import Story
from .serializers import StorySerializer
from django.utils import timezone


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def create_story(request):
    serializer = StorySerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        # Optional: prevent duplicates
        # Story.objects.filter(user=request.user).delete()
        serializer.save(user=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from .models import Story, Follow
from django.utils import timezone
from django.db.models import Q
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_stories(request):
    user = request.user

    # Get followed users
    followed_users = RegisterUser.objects.filter(
        followers__follower=user
    )

    users_to_fetch = list(followed_users) + [user]
    stories = Story.objects.filter(user__in=users_to_fetch)

    serializer = StorySerializer(stories, many=True, context={'request': request})
    return Response(serializer.data, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_like_story(request, story_id):
    try:
        story = Story.objects.get(id=story_id)
    except Story.DoesNotExist:
        return Response({"error": "Story not found"}, status=404)

    user = request.user
    if user in story.likes.all():
        story.likes.remove(user)
        liked = False
    else:
        story.likes.add(user)
        liked = True

    return Response({
        "liked": liked,
        "liked_by": story.liked_by()
    })


