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
    if not session_user_pk or session_user_pk != request.user.pk:
        logger.warning(f"Session mismatch or invalid session_user_pk: {session_user_pk}")
        return False

    return True


