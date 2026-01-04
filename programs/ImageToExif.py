class ImageToExif:
    def extract_exif_all(self, image_path):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
        except ImportError:
            raise ImportError("Pillow n'est pas installé")
        infos = {}
        img = Image.open(image_path)
        attrs = {}
        if hasattr(img, "_getexif") and img._getexif():
            for tag_id, v in img._getexif().items():
                nom = TAGS.get(tag_id, tag_id)
                attrs[nom] = v
        for k, v in img.info.items():
            attrs[k] = v
        if hasattr(img, "applist"):
            for item in img.applist:
                if isinstance(item, tuple) and len(item) == 2:
                    key, val = item
                    attrs[str(key)] = val
        return attrs

    def print_exif_all(self, attrs):
        try:
            from PIL.ExifTags import GPSTAGS
        except ImportError:
            print("Pillow n'est pas installé")
            return
        print("=== Exif ===")
        for tag in sorted(attrs):
            value = attrs[tag]
            if tag == "GPSInfo":
                print("GPSInfo :")
                gps_info = {}
                for key in value:
                    name = GPSTAGS.get(key, key)
                    gps_info[name] = value[key]
                for k, v in gps_info.items():
                    print(f"   {k} : {v}")
                lat = self.get_gps_decimal(gps_info, "GPSLatitude", "GPSLatitudeRef")
                lon = self.get_gps_decimal(gps_info, "GPSLongitude", "GPSLongitudeRef")
                if lat is not None and lon is not None:
                    print(f"   --> Latitude: {lat}")
                    print(f"   --> Longitude: {lon}")
            else:
                print(f"{tag}: {value}")

    def get_gps_decimal(self, gps_info, latlon, ref):
        import fractions
        try:
            dms = gps_info.get(latlon)
            ref_value = gps_info.get(ref)
            if dms and ref_value:
                vals = []
                for x in dms:
                    if isinstance(x, tuple):
                        vals.append(float(x[0]) / float(x[1]))
                    elif isinstance(x, fractions.Fraction):
                        vals.append(float(x))
                    else:
                        vals.append(float(x))
                degrees, minutes, seconds = vals
                res = degrees + (minutes/60.0) + (seconds/3600.0)
                if ref_value in ["S", "W"]:
                    res = -res
                return res
        except:
            return None
        return None

    def run(self):
        import os
        while True:
            image_path = input("Chemin vers l'image : ").strip()
            if not os.path.isfile(image_path):
                print("Image introuvable.")
                continuer = input("Continuer... (Entrée pour réessayer, Q pour quitter) : ").strip()
                if continuer.upper() == "Q":
                    break
                else:
                    continue
            try:
                infos = self.extract_exif_all(image_path)
                if not infos:
                    print("Aucune donnée trouvée.")
                else:
                    self.print_exif_all(infos)
            except ImportError as e:
                print(f"Erreur: {e}")
                continuer = input("Continuer... (Entrée pour traiter une autre image, Q pour quitter) : ").strip()
                if continuer.upper() == "Q":
                    break
                else:
                    continue
            except Exception as e:
                print(f"Erreur lors de la lecture de l'image: {e}")
            continuer = input("Continuer... (Entrée pour traiter une autre image, Q pour quitter) : ").strip()
            if continuer.upper() == "Q":
                break

if __name__ == "__main__":
    ImageToExif().run()
