
from django.urls import include, path

urlpatterns = [
    path("coolmsg/", include("EncryptMsg.urls")),
]
