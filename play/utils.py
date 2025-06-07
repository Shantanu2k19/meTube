from play.models import usr 
import logging
logger = logging.getLogger(__name__)

DEMO_USERNAME = "demo_user"
STATUS_NEW = "0"
STATUS_FIRST_LOGIN = "1"
STATUS_EXISTING = "2"


def verifyRequest(request):
    if not request.user.is_authenticated:
        logger.warning("Unauthenticated request.")
        return False
    
    session_user_pk = request.session.get("current_usr_pk")
    curr_usr = usr.objects.get(pk=session_user_pk)
    if curr_usr.username != request.user.username:
        logger.warning("Session user mismatch.")
        return False

    return True


