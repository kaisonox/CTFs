
import pygame
import json
from random import randint

from player import Player
from enemy import Enemy
from explosion import Explosion


class Game:
    def __init__(self, config):
        pygame.init()
        pygame.font.init()
        with open(config, "r") as f:
            config = json.load(f)
        self.config = config
        self.screen_width = config["screen"]["width"]
        self.screen_height = config["screen"]["height"]
        self.screen = pygame.display.set_mode((self.screen_width, self.screen_height))
        self.background = config["screen"]["background"]
        self.clock_tick = config["screen"]["clock_tick"]
        self.numb_enemies = 10
        pygame.display.set_caption("Tank Game")
        self.all_sprites = pygame.sprite.Group()

        self.player = Player(config["player"]["image"], 
                             config["player"]["size"], 
                             config["player"]["health"], 
                             config["player"]["speed"], 
                             self.screen_width / 2,
                             self.screen_height / 2)

        self.all_sprites.add(self.player)

        # enemies
        self.enemies = []
        num_of_enemies = 30
        for _ in range(num_of_enemies):
            direct_x = randint(-1, 1)
            direct_y = randint(-1, 1)
            while direct_x == 0 and direct_y == 0:
                direct_x = randint(-1, 1)
                direct_y = randint(-1, 1)
            enemy = Enemy(config["enemy"]["image"],
                          config["enemy"]["size"],
                          config["enemy"]["health"], 
                          config["enemy"]["speed"], 
                          config["enemy"]["damage"], 
                          direct_x, direct_y, 
                          randint(0, self.screen_width),
                          randint(0, self.screen_height))
            self.enemies.append(enemy)
            self.all_sprites.add(enemy)

        # bullets
        self.player_bullets = []
        self.enemy_bullets = []

        # explosion
        self.explosions = []

        pygame.mixer.music.load(config["audio"]["background"]["music"])
        pygame.mixer.music.set_volume(config["audio"]["background"]["volume"])
        pygame.mixer.music.play(-1)

        self.clock = pygame.time.Clock()
        self.running = True

    def intro(self):
        # intro screen
        intro_font = pygame.font.SysFont("comicsansms", 36)
        button_font = pygame.font.SysFont("comicsansms", 30)

        while True:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit()
                    return False
                elif event.type == pygame.MOUSEBUTTONDOWN:
                    if start_button_rect.collidepoint(event.pos):
                        return True

            # Draw the intro screen
            self.screen.fill(self.background)

            # Draw the text
            intro_text = intro_font.render("Can you survive?", True, (0, 0, 0))
            intro_rect = intro_text.get_rect(center=(self.screen_width / 2, self.screen_height / 2))
            self.screen.blit(intro_text, intro_rect)

            # Draw the start button
            start_button_rect = pygame.Rect(300, 400, 200, 50)
            pygame.draw.rect(self.screen, (0, 0, 0), start_button_rect)
            button_text = button_font.render("Start", True, (255, 255, 255))
            button_rect = button_text.get_rect(center=start_button_rect.center)
            self.screen.blit(button_text, button_rect)

            # Update the display
            pygame.display.flip()

            # Cap the frame rate
            self.clock.tick(self.clock_tick)

    def lastWave(self, is_win):

        while True:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    pygame.quit()
                    return
                
            # allow player to move
            if is_win:
                self.player.playerMove(self.screen_width, self.screen_height)
            
            # allow the rest of explosions to finish
            if len(self.explosions) == 0 and len(self.enemy_bullets) == 0 and len(self.player_bullets) == 0:
                break
            for explosion in self.explosions:
                if explosion.update(1):
                    self.explosions.remove(explosion)
                    self.all_sprites.remove(explosion)

            # allow the rest of player bullets to finish
            for bullet in self.player_bullets:
                bullet_state = bullet.playerBulletMove(self.enemies, self.screen_width, self.screen_height)
                if bullet_state != 0:
                    self.player_bullets.remove(bullet)
                    self.all_sprites.remove(bullet)
                    if bullet_state == 2:
                        explosion = Explosion(self.config["explosion"]["small"]["image"], 
                                            self.config["explosion"]["small"]["size"], 
                                            self.config["audio"]["player"]["hit_by_bullet"],
                                            bullet.rect.x, bullet.rect.y, 
                                            self.config["explosion"]["small"]["timeout"])
                        self.explosions.append(explosion)
                        self.all_sprites.add(explosion)

            # allow the rest of enemy bullets to finish
            for bullet in self.enemy_bullets:
                bullet_state = bullet.enemyBulletMove(self.player, self.screen_width, self.screen_height)
                if bullet_state != 0:
                    self.enemy_bullets.remove(bullet)
                    self.all_sprites.remove(bullet)
                    if bullet_state == 2:
                        explosion = Explosion(self.config["explosion"]["small"]["image"], 
                                            self.config["explosion"]["small"]["size"], 
                                            self.config["audio"]["enemy"]["hit"],
                                            bullet.rect.x, bullet.rect.y, 
                                            self.config["explosion"]["small"]["timeout"])
                        self.explosions.append(explosion)
                        self.all_sprites.add(explosion)


            # Draw the outro screen
            self.screen.fill(self.background)
            self.all_sprites.draw(self.screen)
            if is_win:
                self.player.playerShowHealth(self.screen, pygame.font.SysFont("comicsansms", 15))
            
            pygame.display.flip()
            self.clock.tick(self.clock_tick)

        
        is_outro = True
        if is_win:
            last_wave = []
            # Load the image "graphics/phong_lon.png"
            phong_lon_image = pygame.image.load("./graphics/phong_lon.png")

            speed_of_phong_lons = 5
            num_of_phong_lons = 15

            desired_width = self.screen_width / num_of_phong_lons
            desired_height = desired_width * phong_lon_image.get_height() / phong_lon_image.get_width()
            phong_lon_image = pygame.transform.scale(phong_lon_image, (int(desired_width), int(desired_height)))


            for i in range(num_of_phong_lons):
                # Create a new sprite based on the image
                phong_lon = pygame.sprite.Sprite()
                phong_lon.image = phong_lon_image
                phong_lon.rect = phong_lon.image.get_rect()
                phong_lon.rect.x = i * phong_lon.rect.width
                phong_lon.rect.y = -phong_lon.rect.height
                last_wave.append(phong_lon)
                self.all_sprites.add(phong_lon)

            while is_outro:
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        pygame.quit()
                        return

                # Draw the intro screen
                self.screen.fill(self.background)

                # Move the phong lons down the screen
                for phong_lon in last_wave:
                    phong_lon.rect.y += speed_of_phong_lons
                    # check if phong lon hit player
                    if phong_lon.rect.colliderect(self.player.rect):
                        # player.health = 0
                        self.player.health = 0
                        explosion = Explosion(self.config["explosion"]["big"]["image"], 
                                              self.config["explosion"]["big"]["size"], 
                                              self.config["audio"]["player"]["hit_by_enemy"],
                                              # player location
                                              self.player.rect.x, self.player.rect.y,
                                              self.config["explosion"]["big"]["timeout"])
                        self.explosions.append(explosion)
                        self.all_sprites.add(explosion)
                        self.all_sprites.draw(self.screen)

                        self.player.playerShowHealth(self.screen, pygame.font.SysFont("comicsansms", 15))

                        pygame.display.flip()
                        is_outro = False
                        break

                self.player.playerMove(self.screen_width, self.screen_height)
                self.all_sprites.draw(self.screen)
                self.player.playerShowHealth(self.screen, pygame.font.SysFont("comicsansms", 15))
                # Update the display
                pygame.display.flip()

                # Cap the frame rate
                self.clock.tick(self.clock_tick)

        else:
            pass

        return
    
    def outro(self, is_win):
        try:
            pygame.time.wait(1000)
            pygame.init()
            pygame.font.init()
        except:
            pygame.quit()
            return
        if is_win:
            # show win screen
            outro_font = pygame.font.SysFont("comicsansms", 36)
            flag_enc = [9, 1, 17, 1, 57, 59, 114, 55, 29, 53, 114, 44, 29, 118, 44, 38, 29, 37, 113, 54, 29, 54, 42, 113, 29, 36, 46, 118, 37, 63]
            flag = ""
            for i in flag_enc:
                flag += chr(i ^ 0x42)
            outro_text_list = ["You Lose!", "Just Kidding", flag]
            time_per_text = self.clock_tick * 2
            clock_tick_count = 0
            while True:
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        pygame.quit()
                        return

                # Draw the intro screen
                self.screen.fill(self.background)

                # Draw the text
                if clock_tick_count > 0 and clock_tick_count < time_per_text:
                    outro_text = outro_font.render(outro_text_list[0], True, (0, 0, 0))
                elif clock_tick_count > time_per_text and clock_tick_count < 2 * time_per_text:
                    outro_text = outro_font.render(outro_text_list[1], True, (0, 0, 0))
                elif clock_tick_count > 2 * time_per_text:
                    outro_text = outro_font.render(outro_text_list[2], True, (0, 0, 0))
                else:
                    outro_text = outro_font.render("", True, (0, 0, 0))
                outro_rect = outro_text.get_rect(center=(self.screen_width / 2, self.screen_height / 2))
                self.screen.blit(outro_text, outro_rect)

                clock_tick_count += 1

                # Update the display
                pygame.display.flip()
                self.clock.tick(self.clock_tick)
        else:
            # show lose screen
            outro_font = pygame.font.SysFont("comicsansms", 36)
            while True:
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        pygame.quit()
                        return

                # Draw the intro screen
                self.screen.fill(self.background)

                # Draw the text
                outro_text = outro_font.render("You Lose!", True, (0, 0, 0))
                outro_rect = outro_text.get_rect(center=(self.screen_width / 2, self.screen_height / 2))
                self.screen.blit(outro_text, outro_rect)

                # Update the display
                pygame.display.flip()
                self.clock.tick(self.clock_tick)


    def run(self):
        # game loop
        while self.running:
            # check if player is dead
            if self.player.playerIsDead():
                self.player.kill()
                explosion = Explosion(self.config["explosion"]["big"]["image"], 
                                      self.config["explosion"]["big"]["size"], 
                                      self.config["audio"]["player"]["hit_by_enemy"],
                                      # player location
                                      self.player.rect.x, self.player.rect.y,
                                      self.config["explosion"]["big"]["timeout"])
                self.explosions.append(explosion)
                self.all_sprites.add(explosion)

                # remove player
                self.all_sprites.remove(self.player)
                
                self.running = False
                return 0

            # check if all enemies are dead
            if len(self.enemies) == 0:
                self.running = False
                return 1

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.running = False
                    pygame.quit()
                    return 2
                    
                if event.type == pygame.KEYDOWN and event.key == pygame.K_SPACE:
                    bullet = self.player.playerShoot(self.enemies, 
                                                     self.config["audio"]["player"]["shoot"],
                                                     self.config["player"]["bullet"]["image"], 
                                                     self.config["player"]["bullet"]["size"],
                                                     self.config["player"]["bullet"]["damage"], 
                                                     self.config["player"]["bullet"]["speed"])
                    self.player_bullets.append(bullet)
                    self.all_sprites.add(bullet)
                    pass
            self.player.playerMove(self.screen_width, self.screen_height)

            for enemy in self.enemies:
                enemy.enemyMove(self.screen_width, self.screen_height)
                # check if enemy hit player
                if enemy.rect.colliderect(self.player.rect):
                    self.player.playerHitByEnemy(enemy)
                    enemy.kill()
                    self.enemies.remove(enemy)
                    explosion = Explosion(self.config["explosion"]["big"]["image"], 
                                          self.config["explosion"]["big"]["size"], 
                                          self.config["audio"]["player"]["hit_by_enemy"],
                                          (enemy.rect.x + self.player.rect.x) / 2,
                                          (enemy.rect.y + self.player.rect.y) / 2,
                                          self.config["explosion"]["big"]["timeout"])
                    self.explosions.append(explosion)
                    self.all_sprites.add(explosion)

            # enemy shoot after 1 second
            for enemy in self.enemies:
                if randint(0, self.clock_tick) == 0:
                    bullet = enemy.enemyShoot(self.player, 
                                              self.config["audio"]["enemy"]["shoot"],
                                              self.config["enemy"]["bullet"]["image"], 
                                              self.config["enemy"]["bullet"]["size"],
                                              self.config["enemy"]["bullet"]["damage"], 
                                              self.config["enemy"]["bullet"]["speed"])
                    
                    self.enemy_bullets.append(bullet)
                    self.all_sprites.add(bullet)

            for bullet in self.player_bullets:
                bullet_state = bullet.playerBulletMove(self.enemies, self.screen_width, self.screen_height)
                if bullet_state != 0:
                    self.player_bullets.remove(bullet)
                    self.all_sprites.remove(bullet)
                    if bullet_state == 2:
                        explosion = Explosion(self.config["explosion"]["small"]["image"], 
                                            self.config["explosion"]["small"]["size"], 
                                            self.config["audio"]["player"]["hit_by_bullet"],
                                            bullet.rect.x, bullet.rect.y, 
                                            self.config["explosion"]["small"]["timeout"])
                        self.explosions.append(explosion)
                        self.all_sprites.add(explosion)


            for bullet in self.enemy_bullets:
                pass
                bullet_state = bullet.enemyBulletMove(self.player, self.screen_width, self.screen_height)
                if bullet_state != 0:
                    self.enemy_bullets.remove(bullet)
                    self.all_sprites.remove(bullet)
                    if bullet_state == 2:
                        explosion = Explosion(self.config["explosion"]["small"]["image"], 
                                            self.config["explosion"]["small"]["size"], 
                                            self.config["audio"]["enemy"]["hit"],
                                            bullet.rect.x, bullet.rect.y, 
                                            self.config["explosion"]["small"]["timeout"])
                        self.explosions.append(explosion)
                        self.all_sprites.add(explosion)
            

            for explosion in self.explosions:
                if explosion.update(1):
                    self.explosions.remove(explosion)
                    self.all_sprites.remove(explosion)

            self.screen.fill(self.background)
            self.all_sprites.draw(self.screen)

            self.player.playerShowHealth(self.screen, pygame.font.SysFont("comicsansms", 15))
            for enemy in self.enemies:
                enemy.enemyShowHealth(self.screen, pygame.font.SysFont("comicsansms", 15))


            pygame.display.flip()
            self.clock.tick(self.clock_tick)


    



