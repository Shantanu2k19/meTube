from django.db import models
from datetime import datetime

class usr(models.Model):
    one = '0' 
    two = '1'  
    three = '2' 
    categories = [
        (one, 'new_user,need auth'), 
        (two, 'user_authorised, first login'),
        (three, 'older user'),
    ]
    c_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=64, unique = True)
    name = models.CharField(max_length=64, blank=True)
    email = models.CharField(max_length=64, unique = True)
    password =  models.CharField(max_length=64)
    status = models.CharField( max_length=1,choices=categories, default=one)
    theme = models.IntegerField(default=9)

    yt_id = models.CharField(max_length=64, blank=True)
    yt_title = models.CharField(max_length=64, blank=True)
    yt_thumbnail = models.CharField(max_length=256, blank=True)

    #credentials from oAuth
    token = models.CharField(max_length=256, blank=True)
    refresh_token = models.CharField(max_length=256, blank=True)
    client_id = models.CharField(max_length=256, blank=True)
    client_secret = models.CharField(max_length=256, blank=True)
    scopes = models.CharField(max_length=64, blank=True)
    token_uri = models.CharField(max_length=256, blank=True)

    #fetch details 
    last_online = models.DateField(auto_now_add=True, blank=True, null=True)
    e_tag = models.CharField(max_length=64,blank=True)
    playlist_nos = models.IntegerField(default=0,blank=True)

    def __str__(self):
        return f"{self.username}({self.c_id}) \n" 

class playlists(models.Model):
    user_id = models.ForeignKey(usr, on_delete=models.CASCADE)
    plist_id = models.CharField(max_length=128, primary_key=True)
    etag = models.CharField(max_length=64)
    title = models.CharField(max_length=64)
    thumbnail = models.CharField(max_length=128)
    video_nos = models.IntegerField(default=0,blank=True)

    def __str__(self):
        return f"{self.title} ({self.user_id.username})" 

class videos(models.Model):
    video_db_id = models.AutoField(primary_key=True)
    playlist_fkey = models.ForeignKey(playlists,on_delete=models.CASCADE)
    playlist_id = models.CharField(max_length=64)
    video_id = models.CharField(max_length=128)
    description = models.CharField(max_length=128)
    title = models.CharField(max_length=128)
    thumbnail = models.CharField(max_length=128)

    def __str__(self):
        return f"{self.title[:30]} -> {self.playlist_fkey.title}" 

class video_change(models.Model):
    one = '0' 
    two = '1' 
    #whether seen by the user or not
    status = [
        (one, 'visible'),
        (two, 'hide'),
    ]
    #whether video got deleted or added
    type = [
        (one, 'added'),
        (two, 'deleted'),
    ]

    notification_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(usr,on_delete=models.CASCADE)

    status = models.CharField( max_length=1,choices=status, default=one)
    type = models.CharField( max_length=1,choices=type, default=one)

    #for video
    v_playlistName = models.CharField(max_length=64, blank=True)
    v_title = models.CharField(max_length=128)
    v_description = models.CharField(max_length=128)
    v_thumbnail = models.CharField(max_length=128)


    def __str__(self):
        return f"{self.user_id.username} -> {self.v_playlistName} ({self.v_title[0:30]})" 
    

class playlist_change(models.Model):
    one = '0' 
    two = '1' 
    #whether seen by the user or not
    status = [
        (one, 'visible'),
        (two, 'hide'),
    ]
    #whether video got deleted or added
    type = [
        (one, 'added'),
        (two, 'deleted'),
    ]

    notification_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(usr, on_delete=models.CASCADE)

    status = models.CharField( max_length=1,choices=status, default=one)
    type = models.CharField( max_length=1,choices=type, default=one)

    # for playlist
    p_title = models.CharField(max_length=64)
    p_thumbnail = models.CharField(max_length=128)

    def __str__(self):
        return f"{self.p_title} [{self.type}, {self.status}]  ({self.user_id.username}) " 
    

class user_message(models.Model):
    one = '0' 
    two = '1' 
    type = [
        (one, 'bug'),  
        (two, 'feature'),
    ]
    type = models.CharField( max_length=1,choices=type, default=one)
    mssg_id = models.AutoField(primary_key=True)
    content = models.CharField(max_length=256)
    date = models.DateField(default=datetime.now)
    senderID = models.ForeignKey(usr, on_delete=models.CASCADE)
    senderUName =  models.CharField(max_length=64)

    def __str__(self):
        return f"{self.senderUName}({self.type})- {self.content[0:30]}" 
