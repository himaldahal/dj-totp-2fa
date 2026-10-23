from django.urls import path

from . import api_views, views

app_name = "dj_totp_2fa"

urlpatterns = [
    path("", views.OverviewView.as_view(), name="overview"),
    path("login/", views.TwoFactorLoginView.as_view(), name="login"),
    path("verify/", views.VerifyView.as_view(), name="verify"),
    path("verify/recovery/", views.VerifyView.as_view(recovery=True), name="verify_recovery"),
    path("verify/cancel/", views.CancelView.as_view(), name="cancel"),
    path("setup/", views.SetupView.as_view(), name="setup"),
    path("done/", views.DoneView.as_view(), name="done"),
    path("devices/", views.DevicesView.as_view(), name="devices"),
    path("devices/add/", views.SetupView.as_view(), name="add_device"),
    path("devices/<int:pk>/rename/", views.RenameDeviceView.as_view(), name="rename_device"),
    path("devices/<int:pk>/remove/", views.RemoveDeviceView.as_view(), name="remove_device"),
    path("recovery/", views.RecoveryView.as_view(), name="recovery"),
    path("disable/", views.DisableView.as_view(), name="disable"),
    path("trusted/", views.TrustedView.as_view(), name="trusted"),
    path("trusted/revoke-all/", views.TrustedRevokeView.as_view(), name="trusted_revoke_all"),
    path("trusted/<int:pk>/revoke/", views.TrustedRevokeView.as_view(), name="trusted_revoke"),
    path("api/status/", api_views.StatusApi.as_view(), name="api_status"),
    path("api/verify/", api_views.VerifyApi.as_view(), name="api_verify"),
    path("api/setup/start/", api_views.SetupStartApi.as_view(), name="api_setup_start"),
    path("api/setup/confirm/", api_views.SetupConfirmApi.as_view(), name="api_setup_confirm"),
]
