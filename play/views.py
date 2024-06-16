from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.db import IntegrityError
from django.db.models import Q

from django.contrib.auth.models import User 
from django.shortcuts import render, HttpResponse, redirect
from django.urls import reverse

from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.response import Response

import os
import json
import requests
from datetime import datetime, date

from .models import *

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# create file handler and set level to INFO
file_handler = logging.FileHandler(os.path.join(os.getcwd(),'log_file.log'))
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)


#global vars
# RedirectURI = "http://127.0.0.1:8000/oauth2callback"
RedirectURI = "https://shantanu2k22.pythonanywhere.com/oauth2callback"
myAPIkey = "MY_API_KEY"


def verifyRequest(request):
  if request.session.has_key('current_usr_pk'):
    print("")
  else:
    return False

  if not request.user.is_authenticated or request.session["current_usr_pk"] ==-1:
    print("not authenticated")
    return False
  return True

###########################################################
#                      Ajax                               #
###########################################################


@api_view(('GET',))
def mark_as_read(request):
  """For marking notification as read"""

  if not verifyRequest(request):
    return error(request)


  request_data = request.GET.get('notif_id')
  logger.info(str(request.session["current_usr_pk"])+"@->"+"mark_as_read!")
  logger.info(str(request.session["current_usr_pk"])+"_"+"got notif_id : "+request_data)
  try:
    type_of_notif = request_data[0]
    notif_number = int(request_data[1:len(request_data)])
    if(type_of_notif=='v'):
      logger.info(str(request.session["current_usr_pk"])+"_"+"video")
      inst = video_change.objects.get(notification_id=notif_number)
      inst.status='1'
      inst.save()

    else:
      logger.info(str(request.session["current_usr_pk"])+"_"+"playlist"+ str(notif_number))
      inst = playlist_change.objects.get(notification_id=notif_number)
      inst.status='1'
      inst.save()

  except Exception as e:
    logger.info(str(request.session["current_usr_pk"])+"_error found"+str(e))
    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  context = {
    "message":"success, notification marked as read",
  }
  return Response(context, status=status.HTTP_200_OK)

@api_view(('GET',))
def mark_all_read(request):
  """marking all notification as read"""

  if not verifyRequest(request):
    return error(request)

  logger.info(str(request.session["current_usr_pk"])+"@->"+ "mark_all_read!")
  request_data = request.GET.get('for_table')
  logger.info(str(request.session["current_usr_pk"])+"_"+"got for table : "+request_data)
  try:
    user = usr.objects.get(pk=request.session["current_usr_pk"] )
    if(request_data=='add_vid'):
      inst = video_change.objects.filter(user_id=user, status='0', type='0')
      for x in inst:
        temp = video_change.objects.get(pk=x.notification_id)
        logger.info(str(request.session["current_usr_pk"])+"_"+str(x.notification_id)+x.status)
        temp.status='1'
        logger.info(str(request.session["current_usr_pk"])+"_"+str(x.notification_id)+ x.status)
        temp.save()
    elif(request_data=='del_vid'):
      inst = video_change.objects.filter(user_id=user, status='0', type='1')
      for x in inst:
        temp = video_change.objects.get(pk=x.notification_id)
        temp.status='1'
        temp.save()
    elif(request_data=='del_plst'):
      inst = playlist_change.objects.filter(user_id=user, status='0')
      for x in inst:
        temp = playlist_change.objects.get(pk=x.notification_id)
        temp.status='1'
        temp.save()
    else:
      logger.info(str(request.session["current_usr_pk"])+"_"+"absurd request")

  except Exception as e:
    logger.info(str(request.session["current_usr_pk"])+"_error found"+str(e))
    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

  context = {
    "message":"success, all marked as read",
  }
  return Response(context, status=status.HTTP_200_OK)


@api_view(('GET',))
def theme_ajax(request):
  """For Ajax call from Ui theme change"""

  if not verifyRequest(request):
    return error(request)

  logger.info(str(request.session["current_usr_pk"])+"@->"+"theme_ajax!")

  request_data = request.GET.get('themeNo')
  logger.info(str(request.session["current_usr_pk"])+"_"+"theme selected : "+request_data)
  try:
    user = usr.objects.get(pk=request.session["current_usr_pk"] )
    user.theme=request_data 
    user.save()
  except Exception as e:
    logger.info(str(request.session["current_usr_pk"])+"_error found"+str(e))
    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  context = {
    "message":"success, user preference changed",
  }
  return Response(context, status=status.HTTP_200_OK)

    
@api_view(('GET',))
def message_from_user(request):
  """message from user """

  if not verifyRequest(request):
    return error(request)
  logger.info(str(request.session["current_usr_pk"])+"_"+"@->"+"message_from_user!")
  type = request.GET.get('type')
  message = request.GET.get('message')

  if(type=='bug'):
    typee='0'
  else:
    typee='1'

  logger.info(str(request.session["current_usr_pk"])+"_"+"message received!")
  try:
    user = usr.objects.get(pk=request.session["current_usr_pk"] )
    instance = user_message.objects.create(
      type = typee,
      content = message,
      senderID = user,
      senderUName = user.username,
    )
    instance.save()
  except Exception as e:
    logger.info(str(request.session["current_usr_pk"])+"_error found"+str(e))
    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  context = {
    "message":"success, message received!",
  }
  return Response(context, status=status.HTTP_200_OK)


@api_view(('GET',))
def change_details(request):
  """new name from user """

  if not verifyRequest(request):
    return error(request)


  newName = request.GET.get('name')
  newUname = request.GET.get('uname')
  
  logger.info(str(request.session["current_usr_pk"])+"_"+"@->change_details!")
  user = usr.objects.get(pk=request.session["current_usr_pk"] )
  if(newUname!='0'):
    try:
      logger.info(str(request.session["current_usr_pk"])+"_changing name to "+newUname)
      from django.contrib.auth.models import User 
      uu = User.objects.get(username = user.username)
      user.username=newUname
      uu.username = newUname
      uu.save()
      user.save()
    except Exception as e:
      logger.info(str(request.session["current_usr_pk"])+"_error found"+str(e))

      return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

  if(newName!='0'):
    try:
      logger.info(str(request.session["current_usr_pk"])+"_changing name to "+newName)
      user.name=newName
      user.save()
    except Exception as e:
      logger.info(str(request.session["current_usr_pk"])+"_"+"New name can't be taken!_"+str(e))
      return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

  context = {
    "message":"success, message received!",
  }
  return Response(context, status=status.HTTP_200_OK)



###########################################################
#                      O-Auth                             #
###########################################################

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
CLIENT_SECRETS_FILE = os.path.join(os.getcwd(),"lol.json")
# CLIENT_SECRETS_FILE = os.path.join(os.getcwd(),"lol.json")

SCOPES = ["https://www.googleapis.com/auth/youtube.readonly"]
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def authorize(request):
  print("auth")
  if not verifyRequest(request):
    return error(request)


  # Create flow instance to manage the OAuth
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)

  #authorized redirect URIs in API console
  flow.redirect_uri = RedirectURI

  authorization_url, state = flow.authorization_url(
      access_type='offline',
      include_granted_scopes='true')

  request.session['stat'] = state
  return redirect(authorization_url)

def oauth2callback(request):
  print("oAuth")
  # access denied 
  try:
    str(request).index('error=')
    return redirect("loggedIn")
  except:
    print("accepted")

  # accessed 
  state = request.session['stat']
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)

  flow.redirect_uri = RedirectURI

  #encoding link
  link = request.build_absolute_uri()
  link = str(link)
  s = link.index("code=")
  cut0 = link[0:s+2]
  cut1 = link[s+2:len(link)]
  cut1 = cut1.replace("/","%2F")
  final = cut0+cut1
  authorization_response = final
  flow.fetch_token(authorization_response=authorization_response)

  credentials = flow.credentials
  # Store credentials
  # request.session['credentials'] = credentials_to_dict(credentials)
  # print(request.session['credentials'])

  credentials_dict = credentials_to_dict(credentials)

  # print(credentials_dict)

  credentials = google.oauth2.credentials.Credentials(
    credentials_dict["token"],
    refresh_token = credentials_dict["refresh_token"],
    token_uri = credentials_dict["token_uri"],
    client_id = credentials_dict["client_id"],
    client_secret = credentials_dict["client_secret"],
    scopes = credentials_dict["scopes"])

  youtube = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

  details = youtube.channels().list(mine=True, part='snippet').execute()

  try:
    u = usr.objects.get(pk=request.session["current_usr_pk"] )
    u.yt_id = details['items'][0]['id']
    u.yt_title = details['items'][0]['snippet']['title']
    u.yt_thumbnail = details['items'][0]['snippet']['thumbnails']['medium']['url']

    u.token = credentials_dict['token']
    u.refresh_token = credentials_dict['refresh_token']
    u.client_id = credentials_dict['client_id']
    u.client_secret = credentials_dict['client_secret']
    u.scopes = credentials_dict['scopes'][0]
    u.token_uri = credentials_dict['token_uri']
    u.status = '1'
    u.save()
  except Exception as e:
    messages.info(request, 'Hey, You found a bug! You are maybe trying to authorize again with same account. SOLUTION: Remove myTube access from link :"https://myaccount.google.com/u/0/permissions" and trying again. If not solved, sign up on meTube with new Account. ERROR:'+str(e))
    return render(request,"play/error.html")
  
  return redirect("loggedIn")

def refreshToken(user,request):
  logger.info(str(request.session["current_usr_pk"])+"_"+"AUTH->"+"refreshing token")
  
  url = "https://oauth2.googleapis.com/token?client_id="+user.client_id+"&client_secret="+user.client_secret+"&refresh_token="+user.refresh_token+"&grant_type=refresh_token"
  payload={}
  headers = {}
  response = requests.request("POST", url, headers=headers, data=payload)
  tok = json.loads(response.text)
  # print(response.text)
  if 'error' in tok.keys():
    print("auth revoked from usr")
    print(tok)
    return -1
  user.token=tok['access_token']
  user.save()
  print("token refreshed")
  return 1

def revoke(request):
  logger.info(str(request.session["current_usr_pk"])+"_"+"AUTH->"+"revoke token")
  user=usr.objects.get(pk=request.session["current_usr_pk"] )
  creds = {}
  creds['client_id']=user.client_id
  creds['client_secret']=user.client_secret
  creds['refresh_token']=user.refresh_token
  creds['scopes'] = [user.scopes]
  creds['token']=user.token
  creds['token_uri']=user.token_uri

  # print(type(creds))

  credentials = google.oauth2.credentials.Credentials(creds)
  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})
  # print(type(credentials))
  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    logger.info(str(request.session["current_usr_pk"])+"_"+"token revoked!!")
  else:
    logger.info(str(request.session["current_usr_pk"])+"_"+"error occured "+str(status_code))
  return loggedIn(request)
  

def check_token(user, request):
  logger.info(str(request.session["current_usr_pk"])+"_"+"AUTH->"+"checking token")

  kk = datetime.now()

  #one hour till token expires
  if request.session.has_key('token_check_time'):
    # print(kk.strftime("%H:%M:%S"),'\n',request.session['token_check_time'].strftime("%H:%M:%S"))
    if (kk-request.session['token_check_time']).total_seconds()<3599:
      print("no need to refresh")
      return 1
  
  print('refreshing')

  url = "https://youtube.googleapis.com/youtube/v3/channels?part=id&id="+user.yt_id+"&key="+myAPIkey

  payload={}
  headers = {
    'Authorization': 'Bearer '+user.token
  }
  response = requests.request("GET", url, headers=headers, data=payload)
  if(response.status_code==401):
    return refreshToken(user,request)
  elif(response.status_code==200):
    request.session['token_check_time']=datetime.now()
    return 1
  else:
    print("some other error "+response.status_code)
  return -1




###########################################################
#                    not logged-in                        #
###########################################################


def index(request):
  logout(request)
  request.session["current_usr_pk"] = -1

  count = usr.objects.all().count()
  context = {
    'count':count,
  }
  return render(request, "play/index.html",context)

def handLogin(request):
    if request.method=="POST":
        # Get the post parameters
        loginusername=request.POST['loginusername']
        loginpassword=request.POST['loginpassword']
        user=authenticate(username= loginusername, password= loginpassword)
        if user is not None:
          from datetime import datetime
          noww = datetime.now()
          present = noww.strftime("%d/%m/%Y %H:%M:%S")
          curr_user = usr.objects.get(username=loginusername)
          login(request, user)
          request.session["current_usr_pk"] = curr_user.pk
          logger.info("\nusername : "+ loginusername+ " logged-In at "+str(present))

          #for refresh token handling 
          if request.session.has_key('token_check_time'):
            print('deleting')
            del request.session['token_check_time']
          
          return redirect("loggedIn")
        else:
          messages.info(request, 'Invalid credentials. Please try again!')
          return redirect("index")
    return HttpResponse("index")

def signup_page(request):
  users = usr.objects.all()
  username_list = []
  email_list = []
  for x in users:
    username_list.append(x.username)
    email_list.append(x.email)

  context = {
    'email_list':json.dumps(email_list),
    'username_list':json.dumps(username_list)
  }
  return render(request, "play/signup.html",context)

def signup_view(request):
    if request.method == 'POST':
        username = request.POST["username"]
        password = request.POST["pass1"]
        name = request.POST["name"]
        mail = request.POST["email"]

        # form = UserCreationForm(request.POST)
        user = User.objects.create_user(username=username,email=mail,password=password)
        login(request, user)

        usrr = usr.objects.create(username=username,email=mail, name=name,  password=password)
        usrr.save()

        from datetime import datetime
        noww = datetime.now()
        present = noww.strftime("%d/%m/%Y %H:%M:%S")
        logger.info("\n new signup : "+ username+ " at"+str(present))


        request.session["current_usr_pk"] =usrr.pk

        return redirect("loggedIn")
    else:
        return render(request, "play/index.html")

def logout_handler(request):
  try:
    user = usr.objects.get(pk=request.session["current_usr_pk"] )
    user.last_online = date.today()
    user.save()
    print('last online updated, logginOut')
    logger.info(str(request.session["current_usr_pk"])+"_LOGGEDOUT at "+datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
  except:
    logout(request)
  
  messages.info(request, 'Logged out!')
  return index(request)


def delete_account(request):
  
  if not verifyRequest(request):
    return error(request)

  if request.method == 'POST':
    user = usr.objects.get(pk=request.session["current_usr_pk"] )
    if(user.username=="demo_user"):
      logger.info(str(request.session["current_usr_pk"])+"_"+"hoshiyari! trying to delete demo account")
      messages.info(request,"please contact developer!")
      return render(request,"play/error.html")

    #revoke token
    ref_tok = user.refresh_token
    url = "https://oauth2.googleapis.com/revoke?token="+ref_tok
    payload={}
    headers = {}
    response = requests.request("POST", url, headers=headers, data=payload)
    logger.info(str(request.session["current_usr_pk"])+"_"+'token revoked')

    u = User.objects.get(username = user.username)
    u.delete()           

    logger.info('USER_DELETED')
    user.delete()

    return redirect("index")
  else:
    return render(request, "play/index.html")





###########################################################
#                     Logged-In                           #
###########################################################

def firstFetch(user,request):
  logger.info(str(request.session["current_usr_pk"])+"_"+"$->"+'firstFetch')
  channelID = user.yt_id
  bearer = user.token

  url = "https://youtube.googleapis.com/youtube/v3/playlists?part=snippet,contentDetails&channelId="+channelID+"&key="+myAPIkey+"&maxResults=50"

  payload={}
  headers = {
    'Authorization': 'Bearer '+bearer
  }
  response = requests.request("GET", url, headers=headers, data=payload)

  data = response.text
  data = json.loads(data)

  user.e_tag = data['etag']
  user.playlist_nos = data['pageInfo']['totalResults']
  user.status='2'
  user.save()
  
  for x in data["items"]:
    p_id = x['id']
    p_etag = x['etag']
    p_title = x['snippet']['title']
    p_thumb = x['snippet']['thumbnails']['high']['url']
    p_nos=x['contentDetails']['itemCount']
    try:
      instance = playlists.objects.create(user_id = user, plist_id=p_id, etag=p_etag, title=p_title, thumbnail=p_thumb, video_nos=p_nos)
      instance.save()
    except Exception as e:
      return [-1,e]

    #playlists saved in db 

    logger.info(str(request.session["current_usr_pk"])+"_"+'adding videos to DB')

    #for each playlist, save videos
    url = "https://youtube.googleapis.com/youtube/v3/playlistItems?part=snippet%2CcontentDetails&maxResults=200&playlistId="+p_id+"&key="+myAPIkey
    payload={}
    headers = {
      'Authorization': 'Bearer '+bearer
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    video_data = json.loads(response.text)

    for content in video_data['items']:
      # logger.info(str(request.session["current_usr_pk"])+"_"+content)
      if(content['snippet']['thumbnails'].get('high')==None):
        thumb="lol no"
      else:
        thumb=content['snippet']['thumbnails']['high']['url']
        
      try:
        video_inst = videos.objects.create(
          playlist_fkey= instance,
          playlist_id=p_id,
          video_id=content['contentDetails']['videoId'],
          title=content['snippet']['title'],
          thumbnail=thumb,
          description=content['snippet']['description'][0:63]
        )
        video_inst.save()
        # logger.info(str(request.session["current_usr_pk"])+"_"+content['snippet']['title']+"inserted")
      except Exception as e:
        logger.info(str(request.session["current_usr_pk"])+"_video not saved! maybe similar?_"+str(e))

    # logger.info(str(request.session["current_usr_pk"])+"_"+"from videos : "+str(video_data['pageInfo']['totalResults'])+",from playlist"+str(p_nos))
    # instance.video_nos=video_data['pageInfo']['totalResults']
    # logger.info(str(request.session["current_usr_pk"])+"_"+"PLAYLIST saved : "+p_title)
  
  #finally mark user as db updated
  return 1


def find_changed_videos(changed, user):
  for playlistID in changed:
    #for each playlist, fetch video from YouTube
    url = "https://youtube.googleapis.com/youtube/v3/playlistItems?part=snippet%2CcontentDetails&maxResults=200&playlistId="+playlistID+"&key="+myAPIkey
    payload={}
    headers = {
      'Authorization': 'Bearer '+user.token
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    video_data = json.loads(response.text)

    video_info={}
    # logger.info('\n')
    i=-1
    for info in video_data['items']:
      i=i+1
      video_info[info['contentDetails']['videoId']]=[i,False]  #dict[video_id] = [index, visited]
      # logger.info(str(info['contentDetails']['videoId']))

    # logger.info('\nvideo collected from yt\n_____________\n')

    #fetch video from DB
    db_videos = videos.objects.filter(playlist_id=playlistID)
    for x in db_videos:  #video: playlistid, desc, title, thumbnail
      # logger.info(str(request.session["current_usr_pk"])+"_"+x.video_id)
      
      if(x.video_id in video_info.keys()): 
        #mark as older videos
        video_info[x.video_id] = [video_info[x.video_id][0],True]
        # logger.info(str(request.session["current_usr_pk"])+"_"+"present-"+x.title[0:10])
      else:
        # logger.info(str(request.session["current_usr_pk"])+"_"+"deleted"+x.title[0:10])
        #add in deleted video table
        # logger.info(str(request.session["current_usr_pk"])+"_"+ playlists.objects.get(pk=playlistID).title)
        notif_instace = video_change.objects.create(
          user_id=user,
          type='1',  #error here
          v_playlistName = playlists.objects.get(pk=playlistID).title,
          v_title = x.title[0:63],
          v_description = x.description,
          v_thumbnail = x.thumbnail,
        )
        notif_instace.save() 

        #delete video from DB
        video_inst = videos.objects.get(playlist_fkey=playlistID, video_id=x.video_id)
        video_inst.delete()
  
    # for added videos
    # logger.info(str(request.session["current_usr_pk"])+"_"+"checking")

    for x in video_info:
      # logger.info(str(request.session["current_usr_pk"])+"_"+video_info[x][1])
      if(video_info[x][1]==False):
        # logger.info(str(request.session["current_usr_pk"])+"_"+x+" new video, adding to  DB")
        #adding new video in DB
        index = video_info[x][0]
        vid_id=video_data['items'][index]['contentDetails']['videoId']
        vid_title=video_data['items'][index]['snippet']['title']
        vid_desc=video_data['items'][index]['snippet']['description'][0:63]
        vid_thumb=video_data['items'][index]['snippet']['thumbnails']['high']['url']
        vid_plList_name=playlists.objects.get(pk=playlistID).title

        video_instance = videos.objects.create(
          playlist_fkey = playlists.objects.get(pk=playlistID),
          playlist_id = playlistID, 
          video_id = vid_id,
          description = vid_desc,
          title = vid_title,
          thumbnail = vid_thumb,
        )
        video_instance.save() 

        # logger.info(str(request.session["current_usr_pk"])+"_"+'Adding to notifications')
        notif_instace = video_change.objects.create(
          user_id=user,
          type='0',
          v_playlistName = vid_plList_name,
          v_title = vid_title,
          v_description = vid_desc,
          v_thumbnail = vid_thumb,
        )
        notif_instace.save()


  # logger.info(str(request.session["current_usr_pk"])+"_"+"function ended :)")
  return
  
def compare(user, pkk):
  logger.info(pkk+"_"+"$->"+'compare')

  channelID = user.yt_id
  bearer = user.token
  url = "https://youtube.googleapis.com/youtube/v3/playlists?part=snippet,contentDetails&channelId="+channelID+"&key="+myAPIkey+"&maxResults=50"
  payload={}
  headers = {
    'Authorization': 'Bearer '+bearer
  }
  response = requests.request("GET", url, headers=headers, data=payload)

  if(response.status_code!=200):
    print("error occured while retrieving data : ",response.text)
    return -1

  data = response.text
  # logger.info(str(request.session["current_usr_pk"])+"_"+data)
  data = json.loads(data)

  if(user.e_tag == data['etag']):
    logger.info(pkk+"_"+"no changes detected")
    return 1
  
  # logger.info(user.e_tag)
  # logger.info(data['etag'])
  logger.info(pkk+"_"+"changes detected \n") 
  user.e_tag = data['etag'] 
  user.save()

  temp_plist={}
  i=-1
  for x in data['items']:
    i=i+1
    temp = [i, x['etag'],False]  #index, etag, checked or not
    temp_plist[x['id']]=temp

  #detect changed, added and delete playlists
  changed = []
  plst = playlists.objects.filter(user_id=user) 
  for x in plst:
    #check if present
    if(x.plist_id in temp_plist.keys()): 
      #mark visited
      temp_plist[x.plist_id] = [ temp_plist[x.plist_id][0], temp_plist[x.plist_id][1], True]

      #check if etag same
      if(x.etag==temp_plist[x.plist_id][1]):
        # logger.info(x.title+" is same")
        print("no changes")
      else:
        # logger.info(x.title+" is changed")
        plst_instance = playlists.objects.get(plist_id = x.plist_id)
        plst_instance.etag = temp_plist[x.plist_id][1]
        plst_instance.save()
        changed.append(x.plist_id)

    else:
      # logger.info("deleted playlist, adding notification")
      notif_instace = playlist_change.objects.create(
        user_id=user,
        type='1',
        p_title = x.title,
        p_thumbnail = x.thumbnail
      )
      notif_instace.save()

      # logger.info(str(request.session["current_usr_pk"])+"_"+"delete playlist")
      inst=playlists.objects.filter(plist_id=x.plist_id)
      inst.delete()


  #find added playlists
  for lists in temp_plist:
    if(not temp_plist[lists][2]):
      # logger.info(str(request.session["current_usr_pk"])+"_"+"new playlist found, adding it in DB")
      index = temp_plist[lists][0]
      temp = data['items'][index]
      instance = playlists.objects.create(
        user_id = user,
        plist_id = temp['id'],
        etag = temp['etag'],
        title = temp['snippet']['title'],
        thumbnail = temp['snippet']['thumbnails']['high']['url'],
        video_nos = temp['contentDetails']['itemCount']
      )
      instance.save()

      # logger.info(str(request.session["current_usr_pk"])+"_"+"adding to notifications")
      inst = playlist_change.objects.create(
        user_id = user,
        type = '0', #added
        p_title = temp['snippet']['title'],
        p_thumbnail = temp['snippet']['thumbnails']['high']['url']
      )

  #now, from changed[] list, find deleted/added videos
  # logger.info(pkk+"_"+'Following playlists that were changed:')
  # for pid in changed:
  #   logger.info(str(request.session["current_usr_pk"])+"_"+str(pid))
    
  if(len(changed)>0):
    logger.info(pkk+"_find_changed_videos")
    find_changed_videos(changed,user)

  return 1




def loggedIn(request):
  if not verifyRequest(request):
    return error(request)

  user = usr.objects.get(pk=request.session["current_usr_pk"] )
  logger.info(str(request.session["current_usr_pk"])+"_"+"$->"+'loggedIn')
  logger.info(str(request.session["current_usr_pk"])+"_"+"current user status : "+str(user.status))
  
  if(user.status!='0'):
    tokk = check_token(user, request)
    if(tokk==-1):
      messages.info(request,"Authorization revoked from user, Contact developer!")
      return render(request,"play/error.html")

  if user.status=='0':
    logger.info(str(request.session["current_usr_pk"])+"_"+'new user, need authorization') 
    
  elif user.status=='1':
    logger.info(str(request.session["current_usr_pk"])+"_"+'authorized user, first login')
    first_fetch = firstFetch(user,request)
    if(first_fetch != 1):
      messages.info(request, 'Cannot use this YouTube Channel! Contact Developer')
      messages.info(request,first_fetch[1])
      return render(request,"play/error.html")
  
  elif user.status=='2':
    logger.info(str(request.session["current_usr_pk"])+"_"+'older user')
    check_ = compare(user,str(request.session["current_usr_pk"]))
    if(check_==-1):
      messages.info(request, 'error occured while retrieving data! contact developer')
      return render(request,"play/error.html")

  else:
    logger.info(str(request.session["current_usr_pk"])+"_"+'older user')


  #deleted and added playlists
  p = playlist_change.objects.filter(user_id=user, status='0')
  pAddedCount = p.filter(type='0').count()  #added
  pdeleteCount = p.filter(type='1').count()  #deleted

  pChange = []
  for x in p:
    temp = {
      'title':x.p_title,
      'type':x.type,
      'thumb':x.p_thumbnail,
      'nid':"p"+str(x.notification_id),
      'nid_2':"Dp"+str(x.notification_id),
    }
    pChange.append(temp)
  
  #deleted and added videos
  v = video_change.objects.filter(user_id=user, status='0')
  vAddedCount = v.filter(type='0').count()
  vDeleteCount = v.filter(type='1').count()

  vChange=[]
  for x in v:
    dsp = x.v_description
    if(len(dsp)>128):
      dsp=dsp[0:128]+"..."

    title = x.v_title
    if(len(title)>100):
      title = title[0:100]+"..."

    temp = {
      'title':title,
      'type':x.type,
      'playlist':x.v_playlistName,
      'desc':dsp,
      'thumb':x.v_thumbnail,
      'nid':"v"+str(x.notification_id),
      'nid_2':"Dv"+str(x.notification_id),

    }
    vChange.append(temp)

  #playlist numbers for this user 
  nos = playlists.objects.filter(user_id=user).count()
  user.playlist_nos = nos
  user.save()

  #last online
  today = date.today()
  prev_date = user.last_online
  # if(today.strftime("%d/%m/%Y")>prev_date.strftime("%d/%m/%Y") ):
  #   user.last_online = today
  #   user.save()
  #   print('last online updated')

  temp = today-user.last_online

  thumb_nail = user.yt_thumbnail
  if(len(thumb_nail)<1):
    thumb_nail="/static/img/profile.png"

  name = user.name
  if(len(name)<1):
    name=user.username

  context = {
    'last_online':prev_date.strftime("%d/%m/%Y"),
    'days': temp.days,
    'username':user.username,
    'name': name,
    'email':user.email,
    'photo':thumb_nail,
    'theme':user.theme,

    'pTot': nos,
    'padd': pAddedCount,
    'pdel': pdeleteCount,
    'vadd': vAddedCount,
    'vdel': vDeleteCount,
    'deleted_pl': pChange,
    'deleted_vd': vChange,
    'status' : user.status,
  }
  return render(request,"play/loggedIn.html", context)


def playlists_page(request):

  if not verifyRequest(request):
    return error(request)

  logger.info(str(request.session["current_usr_pk"])+"_"+"$->"+'playlists_page')
  user = usr.objects.get(pk=request.session["current_usr_pk"])

  #playlists 
  plst = playlists.objects.filter(user_id=user)

  data=[]
  playlist_list=[]
  i=0
  for x in plst:
    i+=1
    temp = {
      'sno':i,
      'title':x.title,
      'thumbnail':x.thumbnail,
      'video_no':x.video_nos,
      'link': "https://www.youtube.com/playlist?list="+x.plist_id,
    }
    playlist_list.append(temp)

    video_list=[]
    vds = videos.objects.filter(playlist_id=x.plist_id)
    for vid in vds:
      temp2 = {
        'title':vid.title,
        'desc':vid.description[0:10],
        'thumb':vid.thumbnail,
      }
      video_list.append(temp2)
    
    temp['video_list']=video_list
  
    data.append(temp)
  
  # logger.info(str(request.session["current_usr_pk"])+"_"+str(i))



  # personal data
  thumb_nail = user.yt_thumbnail
  if(len(thumb_nail)<1):
    thumb_nail="/static/img/profile.png"

  name = user.name
  if(len(name)<1):
    name=user.username

  context = {
    'username':user.username,
    'name': name,
    'email':user.email,
    'photo':thumb_nail,
    'theme':user.theme,

    'playlist_list':playlist_list,
    'noOfPlaylists':i,

    'playlist_data':json.dumps(data),
  }
  return render(request,"play/playlists.html", context)


###########################################################
#                    Other pages                          #
###########################################################

def profile(request):

  if not verifyRequest(request):
    return error(request)

  logger.info(str(request.session["current_usr_pk"])+"_"+"$->"+'profile')

  user = usr.objects.get(pk=request.session["current_usr_pk"] )
  thumb_nail = user.yt_thumbnail
  if(len(thumb_nail)<1):
    thumb_nail="/static/img/profile.png"

  name = user.name

  context = {
    'username':user.username,
    'name': name,
    'email':user.email,
    'photo':thumb_nail,
    'last_online':user.last_online,
    'yt_title': user.yt_title,
    'yt_id':user.yt_id,
    'theme':user.theme,

    'uname_js':json.dumps(user.username),
    'name_js':json.dumps(name),
    'yt_id_js':json.dumps(user.yt_id),

  }
  return render(request,"play/profile.html",context)


def error(request):
  messages.info(request, 'Authentication Error! Login Again')
  logger.info("ERROR error occured!")
  return render(request,"play/error.html")




###########################################################
#                     comments                            #
###########################################################

#return render(request, "hello/verified.html",context)
#return HttpResponseRedirect(reverse("index"))
#return render(request, "users/user.html", context)

