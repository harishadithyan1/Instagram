from django.contrib import admin
from .models import RegisterUser,Posts,Follow,Message,Story

admin.site.register(RegisterUser)
admin.site.register(Posts)
admin.site.register(Follow)
admin.site.register(Message)
admin.site.register(Story)
