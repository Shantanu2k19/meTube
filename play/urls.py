from django.urls import path

from . import views

urlpatterns = [
    path("",views.index,name="index"),  

    #login
    path('login', views.handLogin, name="login"),
    path("loggedIn",views.loggedIn, name="loggedIn"),
    path("signup_helper",views.signup_page, name="signup_page"),
    path("signup", views.signup_view, name="signup"),
    path("logout_handler", views.logout_handler, name="logout_handler"),
    path("delete_account", views.delete_account, name="delete_account"),

    #oauth
    path("authorize", views.authorize, name="authorize"),
    path("oauth2callback",views.oauth2callback, name="oauth2callback"),
    path("revoke",views.revoke, name="revoke"),


    path("error",views.error, name="error"),
    path("playlists_page",views.playlists_page, name="playlists_page"),
    path("profile",views.profile,name="profile"),

    #ajax
    path("theme_ajax", views.theme_ajax, name="theme_ajax"),
    path("message_from_user", views.message_from_user, name="message_from_user"),
    path("change_details", views.change_details, name="change_details"),
    
    path("mark_as_read", views.mark_as_read, name="mark_as_read"),
    path("mark_all_read", views.mark_all_read, name="mark_all_read"),

    
]