

import pygame
from random import randint



class Enemy(pygame.sprite.Sprite):
    def __init__(self, image, size, health, speed, damage, direct_x, direct_y, init_x, init_y):
        super().__init__()
        enemy_image = pygame.image.load(image)
        self.image = pygame.transform.scale(enemy_image, size)
        self.rect = self.image.get_rect()
        self.rect.center = (init_x, init_y)
        self.position = self.rect.center
        self.health = health
        self.speed = speed
        self.damage = damage
        self.direct_x = direct_x
        self.direct_y = direct_y


    def enemyShowHealth(self, screen, font):
        text = font.render(str(self.health), True, (255, 0, 0))
        text_rect = text.get_rect()
        text_rect.center = (self.rect.x + self.rect.width / 2, self.rect.y - 10)
        screen.blit(text, text_rect)

    def enemyMove(self, screen_width, screen_height):
        self.rect.x += self.speed * self.direct_x
        self.rect.y += self.speed * self.direct_y

        # check if enemy is out of screen
        if self.rect.left < 0:
            self.rect.left = 0
            self.direct_x = -self.direct_x
        if self.rect.right > screen_width:
            self.rect.right = screen_width
            self.direct_x = -self.direct_x
        if self.rect.top < 0:
            self.rect.top = 0
            self.direct_y = -self.direct_y
        if self.rect.bottom > screen_height:
            self.rect.bottom = screen_height
            self.direct_y = -self.direct_y

        self.position = (self.rect.x + self.rect.width / 2, self.rect.y + self.rect.height / 2)



    def enemyHit(self, player_bullet):
        is_removable = False
        self.health -= player_bullet.damage
        if self.health <= 0:
            self.kill()
            is_removable = True
        return is_removable
    
    def enemyShoot(self, player, sound, bullet_image, bullet_size, bullet_damage, bullet_speed):
        music, volume = pygame.mixer.Sound(sound["sound"]), sound["volume"]
        music.set_volume(volume)
        music.play()
        # Random around player
        delta_x = randint(-50, 50)
        delta_y = randint(-50, 50)
        # Get unit vector
        direct_x = player.rect.x - self.rect.x + delta_x
        direct_y = player.rect.y - self.rect.y + delta_y
        # Convert to unit vector
        dist = (direct_x ** 2 + direct_y ** 2) ** 0.5
        direct_x /= dist
        direct_y /= dist

        # Get closest enemy
        bullet = EnemyBullet(bullet_image, bullet_size, bullet_damage, bullet_speed, direct_x, direct_y)
        
        # Start bullet at enemy position
        bullet.rect.center = self.position
        return bullet

    def kill(self) -> None:
        return super().kill()
        
    


class EnemyBullet(pygame.sprite.Sprite):
    def __init__(self, image, size, damage, speed, direct_x, direct_y):
        super().__init__()
        enemy_image = pygame.image.load(image)
        self.image = pygame.transform.scale(enemy_image, size)
        self.rect = self.image.get_rect()
        self.position = self.rect.center
        self.damage = damage
        self.speed = speed
        self.direct_x = direct_x
        self.direct_y = direct_y

    def enemyBulletMove(self, player, screen_width, screen_height):
        bullet_state = 0
        self.rect.x += self.speed * self.direct_x
        self.rect.y += self.speed * self.direct_y

        # check if bullet is out of screen
        if self.rect.x < 0 or self.rect.x > screen_width or self.rect.y < 0 or self.rect.y > screen_height:
            self.kill()
            bullet_state = 1

        # check if bullet hit player
        if self.rect.colliderect(player.rect):
            player.playerHitByEnemyBullet(self)
            self.kill()
            bullet_state = 2
        
        return bullet_state
    

    def kill(self) -> None:
        return super().kill()
    

