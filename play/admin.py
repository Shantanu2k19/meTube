from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(usr)
admin.site.register(playlists)
admin.site.register(videos)
admin.site.register(video_change)
admin.site.register(playlist_change)
admin.site.register(user_message)
