# Generated by Django 5.2.3 on 2025-06-23 08:50

import cloudinary.models
import django.utils.timezone
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0019_remove_story_video_alter_story_image'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='posts',
            name='image',
        ),
        migrations.RemoveField(
            model_name='story',
            name='image',
        ),
        migrations.AddField(
            model_name='posts',
            name='media',
            field=cloudinary.models.CloudinaryField(default=django.utils.timezone.now, max_length=255, verbose_name='media'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='story',
            name='media',
            field=cloudinary.models.CloudinaryField(default=django.utils.timezone.now, max_length=255, verbose_name='media'),
            preserve_default=False,
        ),
    ]
