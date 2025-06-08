import json
from django.contrib import messages
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from ..models import usr, video_change, playlist_change, user_message

from play.utils import verifyRequest

import logging
logger = logging.getLogger(__name__)

###########################################################
#                      Ajax                               #
###########################################################


@api_view(("GET",))
def mark_as_read(request):
		"""For marking notification as read"""

		if not verifyRequest(request):
			return error(request)

		request_data = request.GET.get("notif_id")
		try:
			logger.info(f"AJAX mark_as_read: for user_pk[{request.session["current_usr_pk"]}], type: [{request_data[0]}]")

			type_of_notif = request_data[0]
			notif_number = int(request_data[1 : len(request_data)])
			if type_of_notif == "v":
					inst = video_change.objects.get(notification_id=notif_number)
					inst.status = "1"
					inst.save()

			else:
					inst = playlist_change.objects.get(notification_id=notif_number)
					inst.status = "1"
					inst.save()

		except Exception as e:
				logger.info(str(request.session["current_usr_pk"]) + "_error found" + str(e))
				return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		context = {
			"message": "success, notification marked as read",
		}
		return Response(context, status=status.HTTP_200_OK)


@api_view(("GET",))
def mark_all_read(request):
	"""marking all notification as read"""

	if not verifyRequest(request):
			return error(request)
	request_data = request.GET.get("for_table")
	try:
		user = usr.objects.get(pk=request.session["current_usr_pk"])
		logger.info(f"AJAX mark_all_read: for {user.username}, user_pk[{request.session["current_usr_pk"]}], request_data [{request_data}]")
		if request_data == "add_vid":
				inst = video_change.objects.filter(user_id=user, status="0", type="0")
				for x in inst:
						temp = video_change.objects.get(pk=x.notification_id)
						temp.status = "1"
						temp.save()
		elif request_data == "del_vid":
				inst = video_change.objects.filter(user_id=user, status="0", type="1")
				for x in inst:
						temp = video_change.objects.get(pk=x.notification_id)
						temp.status = "1"
						temp.save()
		elif request_data == "del_plst":
				inst = playlist_change.objects.filter(user_id=user, status="0")
				for x in inst:
						temp = playlist_change.objects.get(pk=x.notification_id)
						temp.status = "1"
						temp.save()
		else:
				logger.info(str(request.session["current_usr_pk"]) + "_" + "absurd request")

	except Exception as e:
		logger.info(str(request.session["current_usr_pk"]) + "_error found" + str(e))
		return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

	context = {
		"message": "success, all marked as read",
	}
	return Response(context, status=status.HTTP_200_OK)


@api_view(("GET",))
def theme_ajax(request):
	"""For Ajax call from Ui theme change"""

	if not verifyRequest(request):
			return error(request)

	request_data = request.GET.get("themeNo")
	try:
		user = usr.objects.get(pk=request.session["current_usr_pk"])
		logger.info(f"AJAX theme_ajax: for {user.username}, user_pk[{request.session["current_usr_pk"]}], request_data [{request_data}]")
		user.theme = request_data
		user.save()
	except Exception as e:
		logger.info(str(request.session["current_usr_pk"]) + "_error found" + str(e))
		return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
	context = {
			"message": "success, user preference changed",
	}
	return Response(context, status=status.HTTP_200_OK)


@api_view(("GET",))
def message_from_user(request):
	"""message from user"""

	if not verifyRequest(request):
		return error(request)

	type = request.GET.get("type")
	message = request.GET.get("message")

	if type == "bug":
		typee = "0"
	else:
		typee = "1"
	try:
		user = usr.objects.get(pk=request.session["current_usr_pk"])
		logger.info(f"AJAX message_from_user: for {user.username}, user_pk[{request.session["current_usr_pk"]}], typee [{typee}]")
		instance = user_message.objects.create(
			type=typee,
			content=message,
			senderID=user,
			senderUName=user.username,
		)
		instance.save()
	except Exception as e:
		logger.info(str(request.session["current_usr_pk"]) + "_error found" + str(e))
		return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
	context = {
		"message": "success, message received!",
	}
	return Response(context, status=status.HTTP_200_OK)


@api_view(("GET",))
def change_details(request):
	"""new name from user"""

	if not verifyRequest(request):
			return error(request)

	newName = request.GET.get("name")
	newUname = request.GET.get("uname")

	user = usr.objects.get(pk=request.session["current_usr_pk"])
	logger.info(f"AJAX change_details: for {user.username}, user_pk[{request.session["current_usr_pk"]}]")

	if newUname != "0":
		try:
			logger.info(
					str(request.session["current_usr_pk"]) + "_changing name to " + newUname
			)
			from django.contrib.auth.models import User

			uu = User.objects.get(username=user.username)
			user.username = newUname
			uu.username = newUname
			uu.save()
			user.save()
		except Exception as e:
			logger.info(
					str(request.session["current_usr_pk"]) + "_error found" + str(e)
			)

			return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

	if newName != "0":
		try:
			logger.info(
					str(request.session["current_usr_pk"]) + "_changing name to " + newName
			)
			user.name = newName
			user.save()
		except Exception as e:
			logger.info(
					str(request.session["current_usr_pk"])
					+ "_"
					+ "New name can't be taken!_"
					+ str(e)
			)
			return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

	context = {
			"message": "success, message received!",
	}
	return Response(context, status=status.HTTP_200_OK)


###########################################################
#                    Other pages                          #
###########################################################


def profile(request):

		if not verifyRequest(request):
			return error(request)

		user = usr.objects.get(pk=request.session["current_usr_pk"])
		logger.info(f"Profile: {user.username}, user_pk{request.session['current_usr_pk']}")

		thumb_nail = user.yt_thumbnail
		if len(thumb_nail) < 1:
				thumb_nail = "/static/img/profile.png"

		name = user.name

		context = {
				"username": user.username,
				"name": name,
				"email": user.email,
				"photo": thumb_nail,
				"last_online": user.last_online,
				"yt_title": user.yt_title,
				"yt_id": user.yt_id,
				"theme": user.theme,
				"uname_js": json.dumps(user.username),
				"name_js": json.dumps(name),
				"yt_id_js": json.dumps(user.yt_id),
		}
		return render(request, "play/profile.html", context)


def error(request):
		messages.info(request, "Authentication Error! Login Again")
		logger.info("ERROR error occured!")
		return render(request, "play/error.html")


###########################################################
#                     comments                            #
###########################################################

# return render(request, "hello/verified.html",context)
# return HttpResponseRedirect(reverse("index"))
# return render(request, "users/user.html", context)
