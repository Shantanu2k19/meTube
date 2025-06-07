from play.models import usr 
from django.contrib.auth import logout
from django.shortcuts import render

def index(request):
  logout(request)
  request.session["current_usr_pk"] = -1

  count = usr.objects.all().count()
  context = {
    'count':count,
  }
  return render(request, "play/index.html",context)
