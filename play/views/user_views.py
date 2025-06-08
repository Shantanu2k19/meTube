import os
import json
import logging
import requests
from datetime import date, datetime

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.conf import settings
from play.models import usr, playlists, playlist_change, video_change, videos

# Constants
from play.utils import DEMO_USERNAME, STATUS_EXISTING, STATUS_NEW, STATUS_FIRST_LOGIN

# Logger setup
logger = logging.getLogger("play")
logger.setLevel(logging.DEBUG)

from dotenv import load_dotenv
env_path = os.path.join(settings.BASE_DIR, '.env')
load_dotenv(dotenv_path=env_path)

class loggedIn(LoginRequiredMixin, View):
	def get(self, request):
		try:
			user = usr.objects.get(pk=request.session["current_usr_pk"])
			logger.info(f"Loggedin: {user.username}[{user.pk}] status: {user.status}")

			if user.status != STATUS_NEW:
				if self.check_token(user, request) == -1:
					messages.info(request, "Authorization revoked from user, Contact developer!")
					return render(request, "play/error.html")

			if user.status == STATUS_NEW:
				return self.handle_new_user(user, request)
			elif user.status == STATUS_FIRST_LOGIN:
				return self.handle_first_login(user, request)
			elif user.status == STATUS_EXISTING:
				return self.handle_existing_user(user, request)

			return render(request, "play/loggedIn.html", {})

		except Exception as ex:
			logger.exception("Unexpected error in get() method")
			return render(request, "play/error.html")

	def handle_new_user(self, user, request):
		logger.info(f"{user.pk}_new user, need authorization")
		return self.render_dashboard(user)

	def handle_first_login(self, user, request):
		logger.info(f"{user.pk}_authorized user, first login")
		if self.first_fetch(user):
			return self.render_dashboard(user)
		else:
			messages.info(request, "Failed to fetch data from YouTube")
			return render(request, "play/error.html")

	def handle_existing_user(self, user, request):
		# logger.info(f"{user.pk}_older user")
		if self.compare(user, request):
			return self.render_dashboard(user)
		else:
			messages.info(request, "Error occurred while syncing with YouTube")
			return render(request, "play/error.html")

	def render_dashboard(self, user):
		p_changes = playlist_change.objects.filter(user_id=user, status="0")
		v_changes = video_change.objects.filter(user_id=user, status="0")

		context = {
			"last_online": user.last_online.strftime("%d/%m/%Y") if user.last_online else "N/A",
			"days": str((date.today() - user.last_online).days if user.last_online else 0),
			"username": user.username,
			"name": user.name or user.username,
			"email": user.email,
			"photo": user.yt_thumbnail or "/static/img/profile.png",
			"theme": user.theme,
			"pTot": playlists.objects.filter(user_id=user).count(),
			"padd": p_changes.filter(type="0").count(),
			"pdel": p_changes.filter(type="1").count(),
			"vadd": v_changes.filter(type="0").count(),
			"vdel": v_changes.filter(type="1").count(),
			"deleted_pl": [
				{
					"title": x.p_title,
					"type": x.type,
					"thumb": x.p_thumbnail,
					"nid": f"p{x.notification_id}",
					"nid_2": f"Dp{x.notification_id}"
				} for x in p_changes
			],
			"deleted_vd": [
				{
					"title": (x.v_title[:100] + "...") if len(x.v_title) > 100 else x.v_title,
					"type": x.type,
					"playlist": x.v_playlistName,
					"desc": (x.v_description[:128] + "...") if len(x.v_description) > 128 else x.v_description,
					"thumb": x.v_thumbnail,
					"nid": f"v{x.notification_id}",
					"nid_2": f"Dv{x.notification_id}"
				} for x in v_changes
			],
			  'status' : user.status
		}

		user.last_online = date.today()
		user.save()
		return render(self.request, "play/loggedIn.html", context)

	def first_fetch(self, user):
		logger.info(f"{user.pk}_$->firstFetch")
		headers = {"Authorization": f"Bearer {user.token}"}
		url = f"https://youtube.googleapis.com/youtube/v3/playlists?part=snippet,contentDetails&channelId={user.yt_id}&key={os.getenv('myAPIkey')}&maxResults=50"

		playlists_data = self.fetch_paginated_data(url, headers)
		if not playlists_data:
			return False

		for p in playlists_data:
			try:
				plist = playlists.objects.create(
					user_id=user,
					plist_id=p.get("id"),
					etag=p.get("etag"),
					title=p.get("snippet", {}).get("title", ""),
					thumbnail=p.get("snippet", {}).get("thumbnails", {}).get("high", {}).get("url", ""),
					video_nos=p.get("contentDetails", {}).get("itemCount", 0)
				)
				plist.save()

				# Fetch videos in playlist
				vid_url = f"https://youtube.googleapis.com/youtube/v3/playlistItems?part=snippet,contentDetails&maxResults=200&playlistId={plist.plist_id}&key={os.getenv('myAPIkey')}"
				videos_data = self.fetch_paginated_data(vid_url, headers)

				for v in videos_data:
					snippet = v.get("snippet", {})
					title=snippet.get("title", "")
					if title == 'Private video':
						continue
					try:
						videos.objects.create(
							playlist_fkey=plist,
							playlist_id=plist.plist_id,
							video_id=v.get("contentDetails", {}).get("videoId", ""),
							title=snippet.get("title", ""),
							thumbnail=snippet.get("thumbnails", {}).get("high", {}).get("url", ""),
							description=snippet.get("description", "")[:63]
						)
					except Exception as e:
						logger.warning(f"Video not saved: {e}")
			except Exception as e:
				logger.exception("Playlist insert failed")
				return False

		user.status = STATUS_EXISTING
		user.e_tag = json.loads(requests.get(url, headers=headers).text).get("etag", "")
		user.playlist_nos = len(playlists_data)
		user.save()
		return True

	def compare(self, user, request):
		logger.info('---Comparing---')
		self.check_token(user, request)
		headers = {"Authorization": f"Bearer {user.token}"}
		url = f"https://youtube.googleapis.com/youtube/v3/playlists?part=snippet,contentDetails&channelId={user.yt_id}&key={os.getenv('myAPIkey')}&maxResults=50"
		new_data = self.fetch_paginated_data(url, headers)

		if not new_data:
			return False

		current_etag = json.loads(requests.get(url, headers=headers).text).get("etag")
		if user.e_tag == current_etag:
			logger.info('etag same')
			# return True

		user.e_tag = current_etag
		user.save()

		db_playlists = {p.plist_id: p for p in playlists.objects.filter(user_id=user)}
		remote_ids = set()
		changed = []

		for pl in new_data:
			pid = pl.get("id")
			remote_ids.add(pid)
			etag = pl.get("etag")

			if pid in db_playlists:
				if db_playlists[pid].etag != etag:
					db_playlists[pid].etag = etag
					db_playlists[pid].save()
					changed.append(pid)
				del db_playlists[pid]
			else:
				playlists.objects.create(
					user_id=user,
					plist_id=pid,
					etag=etag,
					title=pl["snippet"]["title"],
					thumbnail=pl["snippet"]["thumbnails"]["high"]["url"],
					video_nos=pl["contentDetails"]["itemCount"]
				)
				playlist_change.objects.create(user_id=user, type="0", p_title=pl["snippet"]["title"], p_thumbnail=pl["snippet"]["thumbnails"]["high"]["url"])
		logger.info(f"Total deleted playLists : {len(db_playlists)}")
		logger.info(f"Total changed playLists : {len(changed)}")
  
		for deleted in db_playlists.values():
			playlist_change.objects.create(user_id=user, type="1", p_title=deleted.title, p_thumbnail=deleted.thumbnail)
			deleted.delete()

		if changed:
			self.find_changed_videos(changed, user)

		return True

	def find_changed_videos(self, changed, user):
		for playlist_id in changed:
			try:
				url = (
					f"https://youtube.googleapis.com/youtube/v3/playlistItems"
					f"?part=snippet,contentDetails&maxResults=200"
					f"&playlistId={playlist_id}&key={os.getenv('myAPIkey')}"
				)
				headers = {"Authorization": f"Bearer {user.token}"}
				items = self.fetch_paginated_data(url, headers)

				video_info = {}
				for idx, item in enumerate(items):
					content_details = item.get("contentDetails", {})
					snippet = item.get("snippet", {})
					video_id = content_details.get("videoId")
					title = snippet.get("title", "")

					if video_id and title != 'Private video':
						video_info[video_id] = (idx, item)

				yt_video_ids = set(video_info.keys())

				db_videos = videos.objects.filter(playlist_id=playlist_id)
				db_video_ids = {v.video_id for v in db_videos}

				deleted_ids = db_video_ids - yt_video_ids
				if deleted_ids:
					pl_obj = playlists.objects.filter(plist_id=playlist_id).first()
					for video in db_videos.filter(video_id__in=deleted_ids):
						video_change.objects.create(
							user_id=user,
							type="1",
							v_playlistName=pl_obj.title if pl_obj else "Unknown",
							v_title=video.title[:63],
							v_description=video.description,
							v_thumbnail=video.thumbnail,
						)
						video.delete()

				# Detect added videos
				added_ids = yt_video_ids - db_video_ids
				for vid in added_ids:
					idx, item = video_info[vid]
					snippet = item.get("snippet", {})

					vid_title = snippet.get("title", "")
					vid_desc = snippet.get("description", "")[:63]
					vid_thumb = snippet.get("thumbnails", {}).get("high", {}).get("url", "")

					pl_obj = playlists.objects.filter(plist_id=playlist_id).first()
					if not pl_obj:
						continue

					videos.objects.create(
						playlist_fkey=pl_obj,
						playlist_id=playlist_id,
						video_id=vid,
						description=vid_desc,
						title=vid_title,
						thumbnail=vid_thumb,
					)

					video_change.objects.create(
						user_id=user,
						type="0",  # added
						v_playlistName=pl_obj.title,
						v_title=vid_title,
						v_description=vid_desc,
						v_thumbnail=vid_thumb,
					)
			except Exception as e:
				logger.exception(f"Exception while processing playlist {playlist_id}: {e}")

		return

	def check_token(self, user, request):
		# logger.info(f"{request.session['current_usr_pk']}_AUTH->checking token")
		
		now = datetime.now()
		token_time_str = request.session.get("token_check_time")

		if token_time_str:
			try:
				token_time = datetime.fromisoformat(token_time_str)
				if (now - token_time).total_seconds() < 3599:
					# logger.info("Token is still valid, no refresh needed.")
					return 1
			except ValueError:
				logger.warning("Malformed token_check_time in session. Proceeding to refresh.")

		logger.info("Refreshing token...")
		url = f"https://youtube.googleapis.com/youtube/v3/channels?part=id&id={user.yt_id}&key={os.getenv('myAPIkey')}"
		
		headers = {"Authorization": f"Bearer {user.token}"}
		try:
			response = requests.get(url, headers=headers)
		except Exception as e:
			logger.error(f"Error during token validation request: {e}")
			return -1

		if response.status_code == 200:
			request.session["token_check_time"] = now.isoformat()
			logger.info("Token is valid, session time updated.")
			return 1
		elif response.status_code == 401:
			logger.info("Token expired, attempting to refresh.")
			return self.refresh_token(user, request)
		else:
			logger.error(f"Unexpected error during token check: {response.status_code}")
			return -1

	def refresh_token(self, user, request):
		logger.info(f"{request.session['current_usr_pk']}_AUTH->refreshing token")

		url = "https://oauth2.googleapis.com/token"
		data = {
			"client_id": user.client_id,
			"client_secret": user.client_secret,
			"refresh_token": user.refresh_token,
			"grant_type": "refresh_token"
		}

		try:
			response = requests.post(url, data=data)
			response.raise_for_status()
			token_data = response.json()
		except requests.exceptions.RequestException as e:
			logger.error(f"Token refresh request failed: {e}")
			return -1

		if "access_token" not in token_data:
			logger.error(f"Token refresh failed, response: {token_data}")
			return -1

		user.token = token_data["access_token"]
		user.save()

		request.session["token_check_time"] = datetime.now().isoformat()
		logger.info("Token successfully refreshed.")
		return 1

	def fetch_paginated_data(self, base_url, headers):
		all_items = []
		next_page_token = ""

		while True:
			url = f"{base_url}&pageToken={next_page_token}" if next_page_token else base_url
			response = requests.get(url, headers=headers)
			if response.status_code != 200:
				logger.error(f"Failed to fetch paginated data: {response.status_code}, {response.text}")
				break

			data = response.json()
			all_items.extend(data.get("items", []))
			next_page_token = data.get("nextPageToken")

			if not next_page_token:
				break

		return all_items



class playlists_page(LoginRequiredMixin, View):
	def get(self, request):
		user = usr.objects.get(pk=request.session["current_usr_pk"])
		logger.info(f"Playlist: {user.username}, user_pk{request.session['current_usr_pk']}")

		playlists_qs = playlists.objects.filter(user_id=user).prefetch_related('videos_set')

		playlist_list = []
		playlist_data = []

		for i, pl in enumerate(playlists_qs, start=1):
			videos_qs = videos.objects.filter(playlist_id=pl.plist_id)
			video_list = [
				{
					"title": vid.title,
					"desc": vid.description[:10],
					"thumb": vid.thumbnail,
				}
				for vid in videos_qs
			]

			playlist_info = {
				"sno": i,
				"title": pl.title,
				"thumbnail": pl.thumbnail,
				"video_no": pl.video_nos,
				"link": f"https://www.youtube.com/playlist?list={pl.plist_id}",
				"video_list": video_list,
			}

			playlist_list.append(playlist_info)
			playlist_data.append(playlist_info.copy()) 

		thumb_nail = user.yt_thumbnail or "/static/img/profile.png"
		name = user.name or user.username

		context = {
			"username": user.username,
			"name": name,
			"email": user.email,
			"photo": thumb_nail,
			"theme": user.theme,
			"playlist_list": playlist_list,
			"noOfPlaylists": len(playlist_list),
			"playlist_data": json.dumps(playlist_data),
		}

		return render(request, "play/playlists.html", context)



class DeleteAccountView(LoginRequiredMixin, View):
	def post(self, request):
		user = get_object_or_404(usr, pk=request.session["current_usr_pk"])

		if user.username == DEMO_USERNAME:
			logger.warning(f"{user.pk}_Attempt to delete demo account.")
			messages.info(request, "Demo accounts cannot be deleted. Please contact the developer.")
			return render(request, "play/error.html")

		# Revoke OAuth token
		ref_tok = user.refresh_token
		url = f"https://oauth2.googleapis.com/revoke?token={ref_tok}"
		try:
			response = requests.post(url)
			if response.status_code == 200:
				logger.info(f"{user.pk}_Token successfully revoked.")
			else:
				logger.warning(f"{user.pk}_Token revocation failed: {response.status_code}")
		except requests.exceptions.RequestException as e:
			logger.error(f"{user.pk}_Error revoking token: {e}")

		# Delete Django auth user
		try:
			auth_user = User.objects.get(username=user.username)
			auth_user.delete()
			logger.info(f"{user.pk}_Auth user deleted.")
		except User.DoesNotExist:
			logger.warning(f"{user.pk}_No matching Django auth user found.")

		user.delete()
		logger.info(f"{user.pk}_User profile deleted.")

		return redirect("index")

	def get(self, request):
		return render(request, "play/index.html")
