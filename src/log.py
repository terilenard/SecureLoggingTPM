import logging

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

handler = logging.FileHandler("log_manager.log")
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)