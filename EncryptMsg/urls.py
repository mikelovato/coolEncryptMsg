from django.urls import path

from . import views

urlpatterns = [
    path('send/', views.send_message, name='send_message'),
    path('messages/', views.view_messages, name='view_messages'),
    path('view/plaintextsummary/', views.view_summary_messages, name='view_summary_messages'),
]
