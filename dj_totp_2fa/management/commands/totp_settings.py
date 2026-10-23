from django.core.management.base import BaseCommand

from dj_totp_2fa import conf, settings_registry
from dj_totp_2fa.management.commands._util import table


class Command(BaseCommand):
    help = "List every dj_totp_2fa setting with its current value, or print the Markdown reference."

    def add_arguments(self, parser):
        parser.add_argument("--markdown", action="store_true", help="Print docs/settings.md content.")

    def handle(self, *args, **options):
        if options["markdown"]:
            self.stdout.write(settings_registry.as_markdown())
            return
        rows = []
        for name, s in settings_registry.REGISTRY.items():
            value = conf.raw(name)
            shown = "****" if name == "ENCRYPTION_KEYS" and value else repr(value)
            mark = "" if value == s.default else "*"
            rows.append((name, shown[:60], mark, s.category))
        self.stdout.write(table(rows, ("Setting", "Value", "Set", "Category")))
        for where, key, suggestion in conf.unknown_keys():
            self.stdout.write(self.style.WARNING("Unknown setting %s %s%s" % (where, key, " (did you mean %s?)" % suggestion if suggestion else "")))
