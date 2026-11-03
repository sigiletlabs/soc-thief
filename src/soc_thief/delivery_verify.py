"""One fixed-payload Discord verification; no alert data is read or sent."""
from soc_thief.delivery import DeliveryError, DiscordConfig, DiscordDelivery


def main() -> int:
    try:
        DiscordDelivery(DiscordConfig.from_environment()).verify()
    except (DeliveryError, ValueError):
        print("Discord delivery verification failed; review required.")
        return 1
    print("Discord delivery verification passed; synthetic payload only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
