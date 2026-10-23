from django.dispatch import Signal

totp_device_confirmed = Signal()      # sender=TOTPDevice, device, user, request
totp_device_removed = Signal()        # sender=TOTPDevice, user, name, request
totp_verified = Signal()              # sender=user class, user, request, method
totp_failed = Signal()                # sender=user class, user, request, reason
totp_locked_out = Signal()            # sender=user class, user, request, scope, until
totp_recovery_code_used = Signal()    # sender=user class, user, request, remaining
totp_disabled = Signal()              # sender=user class, user, request, actor
