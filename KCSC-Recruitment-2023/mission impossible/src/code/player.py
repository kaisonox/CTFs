

import pygame



class Player(pygame.sprite.Sprite):
    def __init__(self, image, size, health, speed, init_x, init_y):
        super().__init__()

        player_image = pygame.image.load(image)
        self.image = pygame.transform.scale(player_image, size)
        self.rect = self.image.get_rect()

        self.rect.center = (init_x, init_y)
        self.position = self.rect.center
        self.health = health
        self.speed = speed


    def playerShowHealth(self, screen, font):
        # display health above player
        text = font.render(str(self.health), True, (0, 255, 0))
        text_rect = text.get_rect()
        text_rect.center = (self.rect.x + self.rect.width / 2, self.rect.y - 10)
        screen.blit(text, text_rect)



    def playerMove(self, screen_width, screen_height):
        keys = pygame.key.get_pressed()
        if keys[pygame.K_LEFT] and self.rect.left > 0:
            self.rect.x -= self.speed
        if keys[pygame.K_RIGHT] and self.rect.right < screen_width:
            self.rect.x += self.speed
        if keys[pygame.K_UP] and self.rect.top > 0:
            self.rect.y -= self.speed
        if keys[pygame.K_DOWN] and self.rect.bottom < screen_height:
            self.rect.y += self.speed
        
        self.position = (self.rect.x + self.rect.width / 2, self.rect.y + self.rect.height / 2)

    def playerHitByEnemyBullet(self, enemy_bullet):
        self.health -= enemy_bullet.damage
        pass
    
    def playerHitByEnemy(self, enemy):
        self.health -= enemy.damage
        pass

    def playerShoot(self, enemies, sound, bullet_image, bullet_size, bullet_damage, bullet_speed):
        music, volume = pygame.mixer.Sound(sound["sound"]), sound["volume"]
        music.set_volume(volume)
        music.play()
        # Get closest enemy
        closest_enemy = None
        closest_dist = None
        for enemy in enemies:
            if closest_enemy is None:
                closest_enemy = enemy
                closest_dist = (enemy.rect.x - self.rect.x) ** 2 + (enemy.rect.y - self.rect.y) ** 2
            else:
                dist = (enemy.rect.x - self.rect.x) ** 2 + (enemy.rect.y - self.rect.y) ** 2
                if dist < closest_dist:
                    closest_enemy = enemy
                    closest_dist = dist
        # convert to unit vector
        direct_x = 0
        direct_y = 0
        if closest_enemy is not None:
            dist = (closest_enemy.rect.x - self.rect.x) ** 2 + (closest_enemy.rect.y - self.rect.y) ** 2
            direct_x = (closest_enemy.rect.x - self.rect.x) / dist ** 0.5
            direct_y = (closest_enemy.rect.y - self.rect.y) / dist ** 0.5

    
        bullet = PlayerBullet(bullet_image, bullet_size, bullet_damage, bullet_speed, direct_x, direct_y)
        # start bullet at player's position
        bullet.rect.center = self.position

        return bullet
    
    def playerIsDead(self):
        if self.health <= 0:
            self.kill()
            return True
        else:
            return False
    
    def kill(self) -> None:
        return super().kill()
    



class PlayerBullet(pygame.sprite.Sprite):
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

    def playerBulletMove(self, enemies, screen_width, screen_height):
        bullet_state = 0
        self.rect.x += self.speed * self.direct_x
        self.rect.y += self.speed * self.direct_y

        # check if bullet is out of screen
        if self.rect.x < 0 or self.rect.x > screen_width or self.rect.y < 0 or self.rect.y > screen_height:
            self.kill()
            bullet_state = 1
            return bullet_state

        # check if bullet hit enemy
        for enemy in enemies:
            if pygame.sprite.collide_rect(self, enemy):
                if enemy.enemyHit(self):
                    enemies.remove(enemy)
                    enemy.kill()
                self.kill()
                bullet_state = 2
                break
        return bullet_state
    

    def kill(self) -> None:
        return super().kill()
    

