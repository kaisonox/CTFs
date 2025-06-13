
if __name__ == "__main__":
    import os
    import psutil
    
    # resolve parent process name
    parent = psutil.Process(os.getppid())
    parent_name = parent.name()

    
    if parent_name in ["GamePlay", "GameStart"]:
        from game import Game

        def start(config_file_path="./config/config.json"):
            game = Game(config_file_path)
            start = game.intro()
            if not start:
                return
            is_win = game.run()
            if is_win != 2:
                try:
                    game.lastWave(is_win)
                    game.outro(is_win)
                except:
                    pass
        
        start()

