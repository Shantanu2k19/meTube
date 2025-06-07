from django.urls import path

from .views import auth_views, other_views, index_views, user_views

urlpatterns = [
    path("",index_views.index,name="index"),  

    #login
    path('login', auth_views.handLogin, name="login"),
    path("loggedIn", user_views.loggedIn.as_view(), name="loggedIn"),
    path("signup_helper",auth_views.signup_page, name="signup_page"),
    path("signup", auth_views.signup_view, name="signup"),
    path("logout_handler", auth_views.logout_handler, name="logout_handler"),
    path("delete_account", user_views.DeleteAccountView.as_view(), name="delete_account"),

    #oauth
    path("authorize", auth_views.authorize, name="authorize"),
    path("oauth2callback",auth_views.oauth2callback, name="oauth2callback"),
    path("revoke",auth_views.revoke, name="revoke"),


    path("error",other_views.error, name="error"),
    path("playlists_page",user_views.playlists_page.as_view(), name="playlists_page"),
    path("profile",other_views.profile,name="profile"),

    #ajax
    path("theme_ajax", other_views.theme_ajax, name="theme_ajax"),
    path("message_from_user", other_views.message_from_user, name="message_from_user"),
    path("change_details", other_views.change_details, name="change_details"),
    
    path("mark_as_read", other_views.mark_as_read, name="mark_as_read"),
    path("mark_all_read", other_views.mark_all_read, name="mark_all_read"),

    
]