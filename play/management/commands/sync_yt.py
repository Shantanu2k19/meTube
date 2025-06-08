from django.core.management.base import BaseCommand
from play.models import usr
from play.views.user_views import loggedIn 
from django.test import RequestFactory
from datetime import datetime
import logging
logger = logging.getLogger(__name__)
log_tag = '[CRON]'

class Command(BaseCommand):
    help = 'Sync YouTube playlists and videos for all authorized users'
    logger.info(f"{log_tag} Running cron at: {datetime.now().strftime('%d %m %y : %H %M %S')}")
    
    def handle(self, *args, **kwargs):
        fake_request = RequestFactory().get("/")
        users = usr.objects.exclude(status="0")

        syncer = loggedIn()
        logger.info(f"{log_tag} Total users: {users.count()}")

        for user in users:
            fake_request.session = {"current_usr_pk": user.pk}
            logger.info(f'{log_tag} processing : {user.username}')
            if user.status == "1":
                logger.info(f'{log_tag} first time user')
                syncer.first_fetch(user)
            elif user.status == "2":
                syncer.compare(user)
                logger.info(f'{log_tag} Comparing user2 case')
