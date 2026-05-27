using Raylib_cs;
using System.Numerics;

// Nonogram game (37x37) using raylib-cs. Split into 4 overlapping 20x20 regions for reverse engineering challenge.
// User must solve all regions to reveal the full QR code.
static class Nono
{
    public enum CellState
    {
        Unknown = 0,
        Filled = 1
    }

    public enum Region
    {
        A = 0,
        B = 1,
        C = 2,
        D = 3
    }

    public static void Run(string[] args)
    {
        // Initialize 37x37 main grid
        CellState[,] mainGrid = new CellState[37, 37];
        
        // Check for debug mode - auto-fill grid from file
        if (args.Length > 0 && args[0].EndsWith(".txt"))
        {
            LoadGridFromFile(mainGrid, args[0]);
        }
        
        // Get region clues
        var regionClues = GetRegionClues();
        
        // Track which regions are solved
        bool[] regionSolved = new bool[4];
        bool allSolved = false;

        // Layout constants (no clues visible). Add 4-module quiet zone for QR scannability
        int cellSize = 18; // pixel size
        int quietModules = 4;
        int padding = 20;
        int gridWidthPx = (37 + quietModules * 2) * cellSize;
        int gridHeightPx = (37 + quietModules * 2) * cellSize;
        int windowWidth = gridWidthPx + padding * 2;
        int windowHeight = gridHeightPx + padding * 2;

        Raylib.InitWindow(windowWidth, windowHeight, "Nono");
        Raylib.SetTargetFPS(60);

        while (!Raylib.WindowShouldClose())
        {
            // Input
            Vector2 mouse = Raylib.GetMousePosition();
            bool leftPressed = Raylib.IsMouseButtonPressed(MouseButton.Left);
            bool rightPressed = Raylib.IsMouseButtonPressed(MouseButton.Right);

            // Paint cell on click
            (int gr, int gc) = ScreenToCell(mouse, padding + quietModules * cellSize, padding + quietModules * cellSize, cellSize, 37, 37);
            if (gr >= 0 && gc >= 0)
            {
                if (leftPressed)
                {
                    // Left click toggles black/white for convenience
                    ToggleCell(ref mainGrid[gr, gc], CellState.Filled);
                }
                else if (rightPressed)
                {
                    // Right click clears to white
                    mainGrid[gr, gc] = CellState.Unknown;
                }
            }

            // Check region solutions (re-validate all every frame)
            allSolved = true;
            for (int i = 0; i < 4; i++)
            {
                regionSolved[i] = ValidateRegion(mainGrid, (Region)i, regionClues);
                if (!regionSolved[i])
                {
                    allSolved = false;
                }
            }

            // Draw
            Raylib.BeginDrawing();
            Raylib.ClearBackground(new Raylib_cs.Color(245, 245, 245, 255));

            // Draw main grid cells with quiet zone
            DrawGrid(mainGrid, padding + quietModules * cellSize, padding + quietModules * cellSize, cellSize, 0);

            // Draw grid lines during play only, skip when solved to improve scannability
            if (!allSolved)
            {
                DrawGridLines(37, 37, padding + quietModules * cellSize, padding + quietModules * cellSize, cellSize, 1.5f);
            }

            // Show success message when all regions are solved (positioned to not cover QR code)
            if (allSolved)
            {
                DrawSuccessMessage(windowWidth, windowHeight, 30);
            }

            Raylib.EndDrawing();
        }

        Raylib.CloseWindow();
    }

    private static void LoadGridFromFile(CellState[,] grid, string filePath)
    {
        try
        {
            string[] lines = File.ReadAllLines(filePath);
            
            if (lines.Length != 37)
            {
                Console.WriteLine($"Warning: Expected 37 lines, got {lines.Length}");
            }
            
            for (int r = 0; r < Math.Min(lines.Length, 37); r++)
            {
                string line = lines[r].Trim();
                if (line.Length != 37)
                {
                    Console.WriteLine($"Warning: Line {r + 1} has {line.Length} characters, expected 37");
                }
                
                for (int c = 0; c < Math.Min(line.Length, 37); c++)
                {
                    grid[r, c] = line[c] == '1' ? CellState.Filled : CellState.Unknown;
                }
            }
            
            Console.WriteLine($"Loaded grid from {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading grid from {filePath}: {ex.Message}");
        }
    }

    private static void ToggleCell(ref CellState state, CellState target)
    {
        if (state == target)
        {
            state = CellState.Unknown;
        }
        else
        {
            state = target;
        }
    }

    private static (int, int) ScreenToCell(Vector2 mouse, int originX, int originY, int cellSize, int rows, int cols)
    {
        int mx = (int)mouse.X - originX;
        int my = (int)mouse.Y - originY;
        if (mx < 0 || my < 0) return (-1, -1);
        int c = mx / cellSize;
        int r = my / cellSize;
        if (r < 0 || r >= rows || c < 0 || c >= cols) return (-1, -1);
        return (r, c);
    }

    private static void DrawGrid(CellState[,] grid, int originX, int originY, int cellSize, int gutter)
    {
        int rows = grid.GetLength(0);
        int cols = grid.GetLength(1);
        for (int r = 0; r < rows; r++)
        {
            for (int c = 0; c < cols; c++)
            {
                int x = originX + c * cellSize;
                int y = originY + r * cellSize;
                // Each module is fully filled black if Filled, else white
                Raylib.DrawRectangle(x, y, cellSize, cellSize, grid[r, c] == CellState.Filled ? new Raylib_cs.Color(0, 0, 0, 255) : new Raylib_cs.Color(255, 255, 255, 255));
            }
        }
    }

    private static void DrawGridLines(int rows, int cols, int originX, int originY, int cellSize, float thickness)
    {
        // Grid lines for visual guidance during play - make them more visible
        Raylib_cs.Color gridColor = new Raylib_cs.Color(150, 150, 150, 255); // Darker gray, full opacity
        for (int r = 0; r <= rows; r++)
        {
            int y = originY + r * cellSize;
            Raylib.DrawLineEx(new Vector2(originX, y), new Vector2(originX + cols * cellSize, y), thickness, gridColor);
        }
        for (int c = 0; c <= cols; c++)
        {
            int x = originX + c * cellSize;
            Raylib.DrawLineEx(new Vector2(x, originY), new Vector2(x, originY + rows * cellSize), thickness, gridColor);
        }
    }

    private static Dictionary<Region, (List<List<int>>, List<List<int>>)> GetRegionClues()
    {
        var clues = new Dictionary<Region, (List<List<int>>, List<List<int>>)>();

        // Region A clues (start: row 0, col 0)
        var A0_clues = new List<List<int>>
        {
            new() {7, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 3, 1, 1, 1, 1, -1, -1, -1},
            new() {1, 3, 1, 1, 4, -1, -1, -1, -1, -1},
            new() {1, 3, 1, 1, 1, 1, -1, -1, -1, -1},
            new() {1, 3, 1, 1, 2, 2, -1, -1, -1, -1},
            new() {1, 1, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {7, 1, 1, 1, 1, 1, 1, -1, -1, -1},
            new() {1, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {5, 5, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 3, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 1, 5, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 3, 3, 2, -1, -1, -1, -1, -1},
            new() {3, 1, 2, 2, 2, -1, -1, -1, -1, -1},
            new() {2, 2, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 2, 2, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 2, 3, -1, -1, -1, -1, -1},
            new() {3, 2, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {2, 7, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 5, 1, -1, -1, -1, -1, -1, -1, -1}
        };

        var A1_clues = new List<List<int>>
        {
            new() {7, 1, 2, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 3, 1, 1, 1, 1, 1, -1, -1, -1},
            new() {1, 3, 1, 3, 1, -1, -1, -1, -1, -1},
            new() {1, 3, 1, 1, 1, 1, -1, -1, -1, -1},
            new() {1, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {7, 1, 1, 1, 1, 1, 1, -1, -1, -1},
            new() {1, 1, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 1, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 8, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 10, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 3, 2, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {1, 3, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 1, 10, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 8, -1, -1, -1, -1, -1, -1},
            new() {2, 1, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {3, 1, 2, 4, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 8, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 3, 4, -1, -1, -1, -1, -1, -1}
        };


        // Region B clues (start: row 0, col 17)
        var B0_clues = new List<List<int>>
        {
            new() {1, 1, 2, 7, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 1, 1, -1, -1, -1, -1, -1},
            new() {2, 1, 1, 1, 1, 3, 1, -1, -1, -1},
            new() {1, 1, 1, 3, 1, -1, -1, -1, -1, -1},
            new() {2, 1, 4, 1, 3, 1, -1, -1, -1, -1},
            new() {5, 1, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 1, 1, 1, 7, -1, -1, -1},
            new() {1, 1, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 1, 1, 1, 1, 1, 1, -1},
            new() {2, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {5, 2, 1, 4, -1, -1, -1, -1, -1, -1},
            new() {2, 3, 5, 1, -1, -1, -1, -1, -1, -1},
            new() {2, 4, 2, 1, 3, -1, -1, -1, -1, -1},
            new() {2, 4, 1, 1, 4, -1, -1, -1, -1, -1},
            new() {2, 2, 5, 1, 3, -1, -1, -1, -1, -1},
            new() {2, 2, 1, 2, 1, 1, -1, -1, -1, -1},
            new() {3, 3, 2, 3, 1, -1, -1, -1, -1, -1},
            new() {2, 2, 4, 1, 1, -1, -1, -1, -1, -1},
            new() {6, 1, 1, 1, 2, 3, -1, -1, -1, -1},
            new() {5, 2, 1, 2, 2, -1, -1, -1, -1, -1}
        };

        var B1_clues = new List<List<int>>
        {
            new() {3, 1, 2, 4, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 8, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 3, 4, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 2, 2, -1, -1, -1, -1, -1},
            new() {1, 10, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 1, 7, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {6, 4, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 1, 1, 1, 2, -1, -1, -1, -1},
            new() {7, 3, 3, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 6, -1, -1, -1, -1, -1, -1, -1},
            new() {7, 3, 1, 2, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 1, 1, 1, 3, -1, -1, -1},
            new() {1, 3, 1, 2, 1, 1, 2, -1, -1, -1},
            new() {1, 3, 1, 1, 1, 1, 2, -1, -1, -1},
            new() {1, 3, 1, 1, 3, 1, 1, -1, -1, -1},
            new() {1, 1, 1, 1, 4, 2, -1, -1, -1, -1},
            new() {7, 6, 4, -1, -1, -1, -1, -1, -1, -1}
        };


        // Region C clues (start: row 17, col 0)
        var C0_clues = new List<List<int>>
        {
            new() {3, 2, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {2, 7, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 5, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, -1, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 5, -1, -1, -1, -1, -1, -1},
            new() {3, 7, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {2, 3, 2, 2, 2, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 2, 2, -1, -1, -1, -1, -1},
            new() {1, 4, 2, 2, 1, -1, -1, -1, -1, -1},
            new() {1, 1, 7, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 3, 5, -1, -1, -1, -1, -1, -1},
            new() {3, -1, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {7, 3, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {1, 3, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 3, 1, 1, 1, 2, 2, -1, -1, -1},
            new() {1, 3, 1, 1, 2, 3, -1, -1, -1, -1},
            new() {1, 1, 1, 1, 2, -1, -1, -1, -1, -1},
            new() {7, 2, -1, -1, -1, -1, -1, -1, -1, -1}
        };

        var C1_clues = new List<List<int>>
        {
            new() {1, 1, 1, 5, 7, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 1, 3, 1, -1, -1, -1, -1},
            new() {1, 1, 3, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 3, 1, -1, -1, -1, -1, -1},
            new() {1, 2, 1, 1, 1, 1, 1, -1, -1, -1},
            new() {1, 1, 1, 1, 1, 1, 7, -1, -1, -1},
            new() {2, 1, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {2, 5, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 11, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {3, 11, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 2, 1, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 2, 1, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {3, 6, 2, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 6, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 4, 2, 3, -1, -1, -1, -1, -1, -1},
            new() {3, 5, 2, 1, 1, -1, -1, -1, -1, -1}
        };


        // Region D clues (start: row 17, col 17)
        var D0_clues = new List<List<int>>
        {
            new() {2, 2, 4, 1, 1, -1, -1, -1, -1, -1},
            new() {6, 1, 1, 1, 2, 3, -1, -1, -1, -1},
            new() {5, 2, 1, 2, 2, -1, -1, -1, -1, -1},
            new() {3, 2, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {3, 1, 1, 1, 2, 1, -1, -1, -1, -1},
            new() {6, 1, 1, 2, 2, 2, -1, -1, -1, -1},
            new() {2, 1, 1, 3, 1, 2, -1, -1, -1, -1},
            new() {2, 4, 4, -1, -1, -1, -1, -1, -1, -1},
            new() {3, 1, 1, 1, 2, 1, -1, -1, -1, -1},
            new() {4, 2, 1, 2, -1, -1, -1, -1, -1, -1},
            new() {3, 1, 3, 1, -1, -1, -1, -1, -1, -1},
            new() {3, 1, 5, 1, -1, -1, -1, -1, -1, -1},
            new() {3, 1, 2, 1, -1, -1, -1, -1, -1, -1},
            new() {6, 3, 1, 5, -1, -1, -1, -1, -1, -1},
            new() {5, 1, 1, 2, -1, -1, -1, -1, -1, -1},
            new() {7, 2, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 1, 5, 1, 1, -1, -1, -1, -1, -1},
            new() {2, 2, 1, 1, 1, 1, -1, -1, -1, -1},
            new() {2, 1, 1, 1, 1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 8, -1, -1, -1, -1, -1, -1}
        };

        var D1_clues = new List<List<int>>
        {
            new() {1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
            new() {2, 4, 2, 3, -1, -1, -1, -1, -1, -1},
            new() {3, 5, 2, 1, 1, -1, -1, -1, -1, -1},
            new() {2, 2, 2, 2, -1, -1, -1, -1, -1, -1},
            new() {2, 2, 2, 2, 1, -1, -1, -1, -1, -1},
            new() {2, 2, 6, 1, -1, -1, -1, -1, -1, -1},
            new() {3, 2, 4, 1, 1, -1, -1, -1, -1, -1},
            new() {1, 2, 1, -1, -1, -1, -1, -1, -1, -1},
            new() {1, 2, 1, 1, -1, -1, -1, -1, -1, -1},
            new() {1, 1, 2, 1, 2, 1, -1, -1, -1, -1},
            new() {2, 3, 1, 1, 3, -1, -1, -1, -1, -1},
            new() {1, 1, 11, 1, -1, -1, -1, -1, -1, -1},
            new() {4, 3, 2, 2, 1, -1, -1, -1, -1, -1},
            new() {1, 1, 1, 1, 2, 1, 2, 2, -1, -1},
            new() {5, 1, 2, 1, 1, 1, 1, -1, -1, -1},
            new() {2, 1, 1, 6, 1, -1, -1, -1, -1, -1},
            new() {1, 3, 2, 2, 1, -1, -1, -1, -1, -1},
            new() {1, 2, 2, 1, 1, 2, 1, -1, -1, -1},
            new() {2, 3, 2, 3, 1, -1, -1, -1, -1, -1},
            new() {7, 2, 4, 3, -1, -1, -1, -1, -1, -1}
        };

        clues[Region.A] = (A0_clues, A1_clues);
        clues[Region.B] = (B0_clues, B1_clues);
        clues[Region.C] = (C0_clues, C1_clues);
        clues[Region.D] = (D0_clues, D1_clues);

        return clues;
    }

    private static bool ValidateRegion(CellState[,] mainGrid, Region region, Dictionary<Region, (List<List<int>>, List<List<int>>)> clues)
    {
        // Get region coordinates
        (int startRow, int startCol) = GetRegionBounds(region);
        
        // Extract 20x20 subgrid from main grid
        CellState[,] subGrid = new CellState[20, 20];
        for (int r = 0; r < 20; r++)
        {
        for (int c = 0; c < 20; c++)
        {
                subGrid[r, c] = mainGrid[startRow + r, startCol + c];
        }
    }

        var (rowClues, colClues) = clues[region];

        // Validate rows
        for (int r = 0; r < 20; r++)
        {
            var runs = ComputeRunsRow(subGrid, r, 20);
            if (!RunsEqual(runs, rowClues[r])) return false;
        }

        // Validate columns
        for (int c = 0; c < 20; c++)
        {
            var runs = ComputeRunsCol(subGrid, c, 20);
            if (!RunsEqual(runs, colClues[c])) return false;
        }

        return true;
    }

    private static (int, int) GetRegionBounds(Region region)
    {
        return region switch
        {
            Region.A => (0, 0),
            Region.B => (0, 17),
            Region.C => (17, 0),
            Region.D => (17, 17),
            _ => (0, 0)
        };
    }

    private static void DrawSuccessMessage(int windowWidth, int windowHeight, int fontSize)
    {
        string message = "!!! SOLVED !!!";
        string instruction = "Hope you enjoyed the challenge!";
        
        // Calculate text dimensions for centering
        int messageWidth = Raylib.MeasureText(message, fontSize);
        int instructionWidth = Raylib.MeasureText(instruction, fontSize - 8);
        
        // Position message at the top center, above the QR code
        int messageX = (windowWidth - messageWidth) / 2;
        int messageY = 10;
        
        // Position instruction below the message
        int instructionX = (windowWidth - instructionWidth) / 2;
        int instructionY = messageY + fontSize + 10;
        
        // Draw with green color for success
        Raylib_cs.Color successColor = new Raylib_cs.Color(0, 200, 0, 255);
        Raylib_cs.Color instructionColor = new Raylib_cs.Color(0, 150, 0, 255);
        
        Raylib.DrawText(message, messageX, messageY, fontSize, successColor);
        Raylib.DrawText(instruction, instructionX, instructionY, fontSize - 8, instructionColor);
    }

    private static List<int> ComputeRunsRow(CellState[,] grid, int r, int cols)
    {
        var runs = new List<int>();
        int current = 0;
        for (int c = 0; c < cols; c++)
        {
            if (grid[r, c] == CellState.Filled)
            {
                current++;
            }
            else
            {
                if (current > 0) { runs.Add(current); current = 0; }
            }
        }
        if (current > 0) runs.Add(current);
        if (runs.Count == 0) runs.Add(0);
        return runs;
    }

    private static List<int> ComputeRunsCol(CellState[,] grid, int c, int rows)
    {
        var runs = new List<int>();
        int current = 0;
        for (int r = 0; r < rows; r++)
        {
            if (grid[r, c] == CellState.Filled)
            {
                current++;
            }
            else
            {
                if (current > 0) { runs.Add(current); current = 0; }
            }
        }
        if (current > 0) runs.Add(current);
        if (runs.Count == 0) runs.Add(0);
        return runs;
    }

    private static bool RunsEqual(List<int> a, List<int> b)
    {
        // Filter out -1 padding values and empty runs
        var filteredA = a.Where(x => x != -1).ToList();
        var filteredB = b.Where(x => x != -1).ToList();
        
        if (filteredA.Count == 1 && filteredA[0] == 0) filteredA = new List<int>();
        if (filteredB.Count == 1 && filteredB[0] == 0) filteredB = new List<int>();
        
        if (filteredA.Count != filteredB.Count) return false;
        for (int i = 0; i < filteredA.Count; i++) if (filteredA[i] != filteredB[i]) return false;
        return true;
    }
}
