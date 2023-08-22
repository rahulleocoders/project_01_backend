from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login'),
    path('register/',RegistrationAPI.as_view(),name='register'),
    path('register/<int:id>',RegistrationAPI.as_view(),name='register'),

    path('profile-data-change/',ProfileDataChange.as_view(),name='profile-data-change'),

    path('email-otp-verfication/',EmailOtpVerfication.as_view(),name='email-otp-verfication'),

    path('changepassword/<int:id>',ChangePassword.as_view(),name='changepassword'),
 
    path('botroleapi/',BotRoleApi.as_view(),name='botroleapi'), # post
    path('botroleapi/<int:id>',BotRoleApi.as_view(),name='botroleapi'),  #put get delete
    
    path('get-role/<int:id>',GetData_BotRole.as_view(),name='get_role'),  #get the bot role data
    
    path('set-default/<int:id>',Set_Default_Bot_Role.as_view(),name='set_default'),  #default

    path('bulk-upload/',BulkInvitationAPI.as_view(),name='bulk_upload'),
    path('bulk-upload/<int:id>',BulkInvitationAPI.as_view(),name='bulk_upload'),
    path('create-api/',ApiSettingAPI.as_view(),name='create_api'),
    path('delete-api/<int:id>',ApiSettingAPI.as_view(),name='delete_api'),
    
    path('Langauge-add/',AdminLangaugeAdd.as_view(),name='Langauge_add'),
    path('Langauge-list/',SearchLangauge.as_view(),name='Langauge_list'),

    path('font-add/',AdminFontAdd.as_view(),name='font_add'),
    path('font-list/',SearchFont.as_view(),name='font_list'),

    path('forget-password/',ForgetPassword.as_view(),name='forget_password'),
    path('reset-password/',ResetPassword.as_view(),name='reset_password'),
    
    path('document/',DocumnetsAPI.as_view(),name='document'), #post
    path('document/<int:id>',DocumnetsAPI.as_view(),name='document'), #get, delete, put

    path('prompt-api/<int:id>',PromptsAPI.as_view(),name='prompt_api'), #get

    path('get-document/<int:id>',GetDocumentsAPI.as_view(),name='get_document'), # get data from edit form

    path('get-document-count/<int:id>',GetDoucmentsCount.as_view(),name='get_document_count'), #get the count for dashboard

    path('document-header-footer/',Header_Foorter_Document.as_view(),name='document_header_footer'), #post, put
    path('document-header-footer/<int:id>',Header_Foorter_Document.as_view(),name='document_header_footer'), #get,


    path('text-setting-documents/',Text_Setting_Documents.as_view(),name='text_setting_documents'), #post, put
    path('text-setting-documents/<int:id>',Text_Setting_Documents.as_view(),name='text_setting_documents'), #get,
    
]
