


import pygame


class Explosion(pygame.sprite.Sprite):
    def __init__(self, image, size, music, init_x, init_y, timeout):
        super().__init__()
        explosion_image = pygame.image.load(image)
        self.image = pygame.transform.scale(explosion_image, size)

        sound, volume = pygame.mixer.Sound(music["sound"]), music["volume"]
        sound.set_volume(volume)
        sound.play()
        
        self.rect = self.image.get_rect()
        self.rect.center = (init_x, init_y)
        self.timer = 0
        self.timeout = timeout

    def update(self, dt):
        is_removable = False
        self.timer += dt
        if self.timer >= self.timeout:
            self.kill()
            is_removable = True
        return is_removable


    def kill(self) -> None:
        return super().kill()
    



