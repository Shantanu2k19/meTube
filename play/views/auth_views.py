import os
import json
import logging
import requests
from datetime import datetime, date

from django.conf import settings
from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from play.models import usr
from .index_views import index
from .user_views import loggedIn

# Logger setup
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def handLogin(request):
		if request.method == "POST":
				# Get the post parameters
				loginusername = request.POST["loginusername"]
				loginpassword = request.POST["loginpassword"]
				user = authenticate(username=loginusername, password=loginpassword)
				if user is not None:
						from datetime import datetime

						noww = datetime.now()
						present = noww.strftime("%d/%m/%Y %H:%M:%S")
						curr_user = usr.objects.get(username=loginusername)
						login(request, user)
						request.session["current_usr_pk"] = curr_user.pk
						logger.info(
								"\nusername : " + loginusername + " logged-In at " + str(present)
						)

						# for refresh token handling
						if request.session.has_key("token_check_time"):
								print("deleting")
								del request.session["token_check_time"]

						return redirect("loggedIn")
				else:
						messages.info(request, "Invalid credentials. Please try again!")
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
				"email_list": json.dumps(email_list),
				"username_list": json.dumps(username_list),
		}
		return render(request, "play/signup.html", context)



def signup_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("pass1", "")
        name = request.POST.get("name", "").strip()
        mail = request.POST.get("email", "").strip()

        if usr.objects.count() > 15:
            messages.info(request, "Max user count reached! Cannot create more accounts :(")
            return render(request, "play/index.html")

        try:
            if User.objects.filter(username=username).exists() or usr.objects.filter(username=username).exists():
                messages.error(request, "Username already taken.")
                return render(request, "play/index.html")

            if User.objects.filter(email=mail).exists() or usr.objects.filter(email=mail).exists():
                messages.error(request, "Email already registered.")
                return render(request, "play/index.html")

            user = User.objects.create_user(username=username, email=mail, password=password)
            login(request, user)

            usrr = usr.objects.create(username=username, email=mail, name=name, password=password)

            logger.info(f"New signup: {username} at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            request.session["current_usr_pk"] = usrr.pk

            return redirect("loggedIn")

        except Exception as ex:
            logger.error(f"Exception occurred during signup: {ex}")
            messages.error(request, "Some error occurred! Please try again.")
            return render(request, "play/index.html")

    return render(request, "play/index.html")

def logout_handler(request):
	try:
			user = usr.objects.get(pk=request.session["current_usr_pk"])
			user.last_online = date.today()
			user.save()
			print("last online updated, logginOut")
			logger.info(
					str(request.session["current_usr_pk"])
					+ "_LOGGEDOUT at "
					+ datetime.now().strftime("%d/%m/%Y %H:%M:%S")
			)
	except:
			logout(request)

	messages.info(request, "Logged out!")
	return index(request)



###########################################################
#                      O-Auth                             #
###########################################################

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
CLIENT_SECRETS_FILE = os.path.join(os.getcwd(), "client_secret.json")

SCOPES = ["https://www.googleapis.com/auth/youtube.readonly"]
API_SERVICE_NAME = "youtube"
API_VERSION = "v3"


def credentials_to_dict(credentials):
		return {
				"token": credentials.token,
				"refresh_token": credentials.refresh_token,
				"token_uri": credentials.token_uri,
				"client_id": credentials.client_id,
				"client_secret": credentials.client_secret,
				"scopes": credentials.scopes,
		}


@login_required
def authorize(request):
		print("auth")
		# Create flow instance to manage the OAuth
		flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
				CLIENT_SECRETS_FILE, scopes=SCOPES
		)

		# authorized redirect URIs in API console
		flow.redirect_uri = (
				os.getenv("RedirectURI")
				if not settings.DEBUG
				else os.getenv("RedirectURIlocal")
		)

		authorization_url, state = flow.authorization_url(
				access_type="offline", include_granted_scopes="true"
		)

		request.session["stat"] = state
		if not state:
			messages.error(request, "Session expired or invalid. Please try logging in again.")
			return redirect("index")
		return redirect(authorization_url)


def oauth2callback(request):
		print("oAuth")
		# access denied
		try:
				str(request).index("error=")
				return redirect("loggedIn")
		except:
				print("accepted")

		# accessed
		state = request.session["stat"]
		flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
				CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
		)

		flow.redirect_uri = (
				os.getenv("RedirectURI")
				if not settings.DEBUG
				else os.getenv("RedirectURIlocal")
		)

		# encoding link
		link = request.build_absolute_uri()
		link = str(link)
		s = link.index("code=")
		cut0 = link[0 : s + 2]
		cut1 = link[s + 2 : len(link)]
		cut1 = cut1.replace("/", "%2F")
		final = cut0 + cut1
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
				refresh_token=credentials_dict["refresh_token"],
				token_uri=credentials_dict["token_uri"],
				client_id=credentials_dict["client_id"],
				client_secret=credentials_dict["client_secret"],
				scopes=credentials_dict["scopes"],
		)

		youtube = googleapiclient.discovery.build(
				API_SERVICE_NAME, API_VERSION, credentials=credentials
		)

		details = youtube.channels().list(mine=True, part="snippet").execute()

		try:
				u = usr.objects.get(pk=request.session["current_usr_pk"])
				u.yt_id = details["items"][0]["id"]
				u.yt_title = details["items"][0]["snippet"]["title"]
				u.yt_thumbnail = details["items"][0]["snippet"]["thumbnails"]["medium"]["url"]

				u.token = credentials_dict["token"]
				u.refresh_token = credentials_dict["refresh_token"]
				u.client_id = credentials_dict["client_id"]
				u.client_secret = credentials_dict["client_secret"]
				u.scopes = credentials_dict["scopes"][0]
				u.token_uri = credentials_dict["token_uri"]
				u.status = "1"
				u.save()
		except Exception as e:
				messages.info(
						request,
						'Hey, You found a bug! You are maybe trying to authorize again with same account. SOLUTION: Remove myTube access from link :"https://myaccount.google.com/u/0/permissions" and trying again. If not solved, sign up on meTube with new Account. ERROR:'
						+ str(e),
				)
				return render(request, "play/error.html")

		return redirect("loggedIn")

def revoke(request):
		logger.info(
				str(request.session["current_usr_pk"]) + "_" + "AUTH->" + "revoke token"
		)
		user = usr.objects.get(pk=request.session["current_usr_pk"])
		creds = {}
		creds["client_id"] = user.client_id
		creds["client_secret"] = user.client_secret
		creds["refresh_token"] = user.refresh_token
		creds["scopes"] = [user.scopes]
		creds["token"] = user.token
		creds["token_uri"] = user.token_uri

		# print(type(creds))

		credentials = google.oauth2.credentials.Credentials(creds)
		revoke = requests.post(
				"https://oauth2.googleapis.com/revoke",
				params={"token": credentials.token},
				headers={"content-type": "application/x-www-form-urlencoded"},
		)
		# print(type(credentials))
		status_code = getattr(revoke, "status_code")
		if status_code == 200:
				logger.info(str(request.session["current_usr_pk"]) + "_" + "token revoked!!")
		else:
				logger.info(
						str(request.session["current_usr_pk"])
						+ "_"
						+ "error occured "
						+ str(status_code)
				)
		return loggedIn(request)
