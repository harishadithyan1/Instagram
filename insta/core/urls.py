# your_app/urls.py
from django.urls import path
from . import views
urlpatterns = [
    path('register/', views.register_user, name='register'),
    path('login/', views.login_view, name='login'),
    path('verify-email/', views.verify_email, name='email'),
    path('reset/<int:user_id>/', views.change_password, name='reset'),
    path('verify/<int:user_id>/', views.verify_otp, name='verify'),
    path('home/',views.home,name="home"),
    path('profile/',views.profile_view,name="profile"),
    path('logout/', views.logout_view, name='logout'),
    path('token/refresh/', views.refresh_token_view),
    path('posts/', views.posts_view, name='posts'),
    path('api/user/update-posts-no/', views.update_posts_no),
    path('profile_friend/', views.profile_friend, name='profile_friend'),
    path('follow/<str:username>/', views.follow_user, name='follow-user'),
    path('follow-count/<str:username>/', views.get_follow_counts, name='follow-count'),
    path('followers/<str:username>/', views.get_followers_list, name='followers-list'),
    path('following/<str:username>/', views.get_following_list, name='following-list'),
    path('followers-following/', views.followers_following_view),
    path('messages/send/', views.send_message, name='chat'),
    path('messages/<str:room_name>/', views.get_messages, name='chat'),
    path('stories/create/', views.create_story, name='create_story'),
    path('stories/', views.get_user_stories, name='get_user_stories'),  
    path('stories/<int:story_id>/like/',views. toggle_like_story, name='toggle_like_story'),
]

