import io
import logging
import unittest

import cv2
import main
import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageFilter


class TamperingDetectionTests(unittest.TestCase):
    CONTENT = "https://example.com/qr-shield-controlled-test"
    PAYMENT_CONTENT = "upi://pay?pa=merchant@upi&pn=Shop&am=10&cu=INR"

    @classmethod
    def setUpClass(cls):
        cls.original = cls.make_qr(cls.CONTENT)

    @staticmethod
    def make_qr(content):
        qr = qrcode.QRCode(
            version=6,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=12,
            border=4,
        )
        qr.add_data(content)
        qr.make(fit=False)
        return qr.make_image(
            fill_color="black",
            back_color="white",
        ).convert("RGB")

    @staticmethod
    def as_bgr(image):
        return cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)

    @classmethod
    def with_sticker(cls, fraction):
        image = cls.original.copy()
        draw = ImageDraw.Draw(image)
        side = round(image.width * fraction)
        x = (image.width - side) // 2
        y = (image.height - side) // 2
        draw.rounded_rectangle(
            (x, y, x + side, y + side),
            radius=max(4, side // 10),
            fill=(250, 250, 250),
            outline=(220, 30, 30),
            width=max(3, image.width // 120),
        )
        return image

    @classmethod
    def with_center_logo(cls):
        image = cls.original.copy()
        draw = ImageDraw.Draw(image)
        side = 140
        x = (image.width - side) // 2
        y = (image.height - side) // 2
        draw.ellipse((x, y, x + side, y + side), fill="white")
        draw.ellipse((x + 12, y + 12, x + side - 12, y + side - 12), fill=(45, 140, 80))
        draw.ellipse((x + 35, y + 35, x + side - 35, y + side - 35), fill="white")
        return image

    @classmethod
    def with_decorative_frame(cls):
        canvas = Image.new("RGB", (800, 800), (250, 250, 250))
        offset = (canvas.width - cls.original.width) // 2
        canvas.paste(cls.original, (offset, offset))
        draw = ImageDraw.Draw(canvas)
        draw.rectangle((40, 40, 759, 759), outline=(20, 90, 170), width=8)
        draw.rectangle((52, 52, 747, 747), outline=(220, 170, 30), width=3)
        return canvas

    @classmethod
    def with_finder_pattern_modification(cls):
        image = cls.original.copy()
        draw = ImageDraw.Draw(image)
        draw.rectangle((48, 48, 132, 132), fill="white")
        return image

    def report_case(self, name, image, content):
        img = self.as_bgr(image)
        decoded = main.decode_qr(img)
        result = main.analyze_tampering(img)
        conditions = {
            "edges": main.check_tampering_edges(img),
            "internal_overlay": main.check_internal_overlay(img),
            "finder": main.check_finder_pattern_consistency(img),
            "sharpness": main.check_image_sharpness(img),
        }
        print(
            f"case={name} decoded={decoded == content} "
            f"score={result['tampering_score']}/85 "
            f"signals={conditions} explanations={result['tampering_reasons']}"
        )
        return decoded == content, result, conditions

    def test_generated_qrs_report_signals_for_controlled_variants(self):
        cases = [
            ("original", self.original, self.CONTENT, True, False, 0),
            ("small-central-overlay-12pct", self.with_sticker(0.12), self.CONTENT, True, True, 30),
            ("large-internal-overlay-25pct", self.with_sticker(0.25), self.CONTENT, True, True, 30),
            ("legitimate-center-logo", self.with_center_logo(), self.CONTENT, True, False, 0),
            ("decorative-outer-frame", self.with_decorative_frame(), self.CONTENT, True, False, 0),
            (
                "synthetic-upi-payment-qr",
                self.make_qr(self.PAYMENT_CONTENT),
                self.PAYMENT_CONTENT,
                True,
                False,
                0,
            ),
            (
                "blurred-qr",
                self.original.filter(ImageFilter.GaussianBlur(2)),
                self.CONTENT,
                True,
                False,
                20,
            ),
            (
                "erased-finder-pattern",
                self.with_finder_pattern_modification(),
                self.CONTENT,
                False,
                False,
                0,
            ),
        ]

        for name, image, content, should_decode, internal_overlay, score in cases:
            with self.subTest(case=name):
                decoded, result, conditions = self.report_case(
                    name,
                    image,
                    content,
                )
                self.assertEqual(decoded, should_decode)
                self.assertEqual(conditions["internal_overlay"], internal_overlay)
                self.assertEqual(result["tampering_score"], score)
                if internal_overlay:
                    self.assertIn(
                        "Possible internal overlay detected; manual review recommended",
                        result["tampering_reasons"],
                    )

    def test_decorative_frame_is_recognized_and_excluded_as_outer_boundary(self):
        img = self.as_bgr(self.with_decorative_frame())
        detector_logger = main.logger
        previous_level = detector_logger.level
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        detector_logger.addHandler(handler)
        detector_logger.setLevel(logging.DEBUG)
        try:
            self.assertFalse(main.check_tampering_edges(img))
        finally:
            detector_logger.removeHandler(handler)
            detector_logger.setLevel(previous_level)

        self.assertIn("outer=True", output.getvalue())


if __name__ == "__main__":
    unittest.main()
