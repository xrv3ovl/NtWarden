#include "pch.h"
#include "PixelOwl.h"
#include "Globals.h"  // for GetTabManager().GetTheme()

namespace PixelOwl {

    enum C : uint8_t {
        _ = 0,
        O,
        F,
        B,
        I,
        N,
        W,
        P,
        S,
        T,
        R,
        K,  // blush pink
        D,  // dark feather detail
    };

    // Indices: _ O  F  B  I  N  W  P  S  T  R  K  D
    //  0=transparent, 1=outline, 2=body, 3=belly, 4=accent,
    //  5=beak/feet, 6=eye-white, 7=pupil, 8=shine, 9=branch-dark, 10=branch-bright,
    //  11=blush, 12=feather-detail

    static const ImU32* GetPalette(Theme theme) {
        // NeonBlueGreen — teal/cyan palette (default)
        static const ImU32 Neon[] = {
            IM_COL32(0,   0,   0,   0),   // _
            IM_COL32(68,  208, 210, 255), // O outline
            IM_COL32(170, 215, 220, 255), // F body
            IM_COL32(110, 175, 195, 255), // B belly
            IM_COL32(154, 214, 226, 255), // I accent
            IM_COL32(255, 194, 116, 255), // N beak/feet
            IM_COL32(220, 255, 250, 255), // W eye white
            IM_COL32(18,  42,  50,  255), // P pupil
            IM_COL32(220, 245, 252, 255), // S shine
            IM_COL32(23,  94,  104, 255), // T branch dark
            IM_COL32(103, 231, 224, 255), // R branch bright
            IM_COL32(255, 160, 180, 255), // K blush
            IM_COL32(60,  140, 162, 255), // D feather detail
        };
        // Dark — silver/slate palette
        static const ImU32 Dark[] = {
            IM_COL32(0,   0,   0,   0),   // _
            IM_COL32(110, 130, 150, 255), // O outline slate
            IM_COL32(160, 178, 195, 255), // F body cool-grey
            IM_COL32(120, 140, 160, 255), // B belly darker slate
            IM_COL32(180, 200, 215, 255), // I accent
            IM_COL32(230, 170,  80, 255), // N beak/feet amber
            IM_COL32(238, 242, 248, 255), // W eye white
            IM_COL32(20,  25,  35,  255), // P pupil
            IM_COL32(255, 255, 255, 220), // S shine
            IM_COL32(55,  70,  88,  255), // T branch dark
            IM_COL32(100, 140, 170, 255), // R branch
            IM_COL32(210, 140, 160, 255), // K blush muted rose
            IM_COL32(80,  105, 130, 255), // D feather detail
        };
        // Light — warm cream/peach palette
        static const ImU32 Light[] = {
            IM_COL32(0,   0,   0,   0),   // _
            IM_COL32(160, 120,  80, 255), // O outline warm brown
            IM_COL32(245, 232, 210, 255), // F body warm cream
            IM_COL32(220, 195, 160, 255), // B belly tan
            IM_COL32(240, 215, 180, 255), // I accent
            IM_COL32(230, 130,  50, 255), // N beak/feet orange
            IM_COL32(255, 252, 240, 255), // W eye white
            IM_COL32(60,  35,  15,  255), // P pupil dark brown
            IM_COL32(255, 255, 240, 220), // S shine
            IM_COL32(100,  70,  40, 255), // T branch dark brown
            IM_COL32(180, 140,  90, 255), // R branch mid-tan
            IM_COL32(255, 180, 190, 255), // K blush soft pink
            IM_COL32(170, 130,  85, 255), // D feather detail
        };
        // Classic — grey/steel ImGui classic look
        static const ImU32 Classic[] = {
            IM_COL32(0,   0,   0,   0),   // _
            IM_COL32(120, 120, 132, 255), // O outline mid grey
            IM_COL32(195, 200, 210, 255), // F body light grey
            IM_COL32(155, 162, 175, 255), // B belly mid grey
            IM_COL32(210, 215, 225, 255), // I accent
            IM_COL32(200, 155,  70, 255), // N beak/feet gold
            IM_COL32(240, 240, 245, 255), // W eye white
            IM_COL32(28,  28,  38,  255), // P pupil dark
            IM_COL32(255, 255, 255, 200), // S shine
            IM_COL32(70,  70,  85,  255), // T branch dark
            IM_COL32(140, 140, 160, 255), // R branch mid
            IM_COL32(220, 155, 170, 255), // K blush lavender-rose
            IM_COL32(110, 115, 130, 255), // D feather detail
        };
        // RedSamurai — crimson/gold palette
        static const ImU32 RedSamurai[] = {
            IM_COL32(0,   0,   0,   0),   // _
            IM_COL32(180,  40,  40, 255), // O outline crimson
            IM_COL32(210, 120,  90, 255), // F body warm rust
            IM_COL32(155,  55,  45, 255), // B belly deep red
            IM_COL32(230, 160, 110, 255), // I accent amber
            IM_COL32(255, 200,  60, 255), // N beak/feet gold
            IM_COL32(255, 245, 220, 255), // W eye white warm
            IM_COL32(40,  10,  10,  255), // P pupil
            IM_COL32(255, 245, 200, 200), // S shine
            IM_COL32(80,  20,  10,  255), // T branch dark
            IM_COL32(190,  80,  40, 255), // R branch
            IM_COL32(255, 160, 160, 255), // K blush soft red
            IM_COL32(140,  60,  40, 255), // D feather detail
        };

        switch (theme) {
        case Theme::Dark:        return Dark;
        case Theme::Light:       return Light;
        case Theme::Classic:     return Classic;
        case Theme::RedSamurai:  return RedSamurai;
        case Theme::NeonBlueGreen:
        default:                 return Neon;
        }
    }


    static constexpr int OwlW = 20;
    static constexpr int OwlH = 24;  // taller for proper owl silhouette

    // Reshaped: pointed ear tufts at top, wide shoulders, tapered lower body.
    // Claws (N) at rows 20-22 are drawn separately AFTER the branch so they
    // appear on top (in front of) the branch.
    static const uint8_t Owl[OwlH][OwlW] = {
        //  ear tufts
        { _,_,_,O,F,_,_,_,_,_,_,_,_,_,_,O,F,_,_,_ },  // 0 left ear tip
        { _,_,O,F,F,O,_,_,_,_,_,_,_,_,O,F,F,O,_,_ },  // 1 ear shafts
        { _,_,O,F,F,F,O,_,_,_,_,_,_,O,F,F,F,O,_,_ },  // 2
        { _,_,_,O,F,F,F,O,O,O,O,O,O,F,F,F,O,_,_,_ },  // 3 top of head, wider
        { _,O,F,F,F,F,F,F,F,F,F,F,F,F,F,F,F,F,O,_ },  // 4 crown
        { _,O,F,F,W,W,W,W,F,F,F,F,W,W,W,W,F,F,O,_ },  // 5 eye row top
        { O,F,F,W,W,W,W,W,F,F,F,F,W,W,W,W,W,F,F,O },  // 6
        { O,F,F,W,W,W,W,W,F,F,F,F,W,W,W,W,W,F,F,O },  // 7 eye mid
        { O,F,F,F,W,W,W,F,F,F,F,F,F,W,W,W,F,F,F,O },  // 8 eye bot
        { O,F,D,F,F,F,F,F,B,N,N,B,F,F,F,F,F,D,F,O },  // 9 beak top
        { O,F,F,D,F,F,F,B,B,N,N,B,B,F,F,F,D,F,F,O },  // 10 beak mid
        { O,F,F,F,D,F,B,B,B,B,B,B,B,B,F,D,F,F,F,O },  // 11 chest top
        { _,O,F,F,F,F,F,B,B,B,B,B,B,F,F,F,F,F,O,_ },  // 12 chest
        { _,O,F,F,F,F,F,B,B,B,B,B,B,F,F,F,F,F,O,_ },  // 13
        { _,_,O,F,F,F,B,B,B,B,B,B,B,B,F,F,F,O,_,_ },  // 14 belly wide
        { _,_,O,B,D,B,B,F,F,F,F,F,F,B,B,D,B,O,_,_ },  // 15 lower body
        { _,_,_,O,B,B,F,F,F,F,F,F,F,F,B,B,O,_,_,_ },  // 16 taper in
        { _,_,_,_,O,B,B,F,D,F,F,D,F,B,B,O,_,_,_,_ },  // 17 taper bottom
        { _,_,_,_,_,O,B,B,B,F,F,B,B,B,O,_,_,_,_,_ },  // 18 leg roots
        { _,_,_,_,_,_,O,O,O,_,_,O,O,O,_,_,_,_,_,_ },  // 19 gap before feet
        // Claws — drawn after branch so they appear in front
        { _,_,_,_,_,O,N,_,_,_,_,_,_,N,O,_,_,_,_,_ },  // 20 ankle left/right
        { _,_,_,_,O,N,_,N,_,_,_,_,N,_,N,O,_,_,_,_ },  // 21 claw spread
        { _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_ },  // 22
        { _,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_ },  // 23
    };
    // Row index of the first claw pixel (drawn explicitly after branch)
    static constexpr int ClawStartRow = 20;

    template<int H, int W>
    static void DrawSprite(ImDrawList* dl, const ImVec2& origin, float pixelSize, const uint8_t(&sprite)[H][W], const ImU32* pal) {
        for (int y = 0; y < H; y++) {
            for (int x = 0; x < W; x++) {
                const uint8_t color = sprite[y][x];
                if (color == _) {
                    continue;
                }

                const ImVec2 p0(origin.x + x * pixelSize, origin.y + y * pixelSize);
                const ImVec2 p1(p0.x + pixelSize, p0.y + pixelSize);
                dl->AddRectFilled(p0, p1, pal[color]);
            }
        }
    }

    static void DrawPixel(ImDrawList* dl, const ImVec2& origin, float pixelSize, int x, int y, uint8_t color, const ImU32* pal) {
        const ImVec2 p0(origin.x + x * pixelSize, origin.y + y * pixelSize);
        const ImVec2 p1(p0.x + pixelSize, p0.y + pixelSize);
        dl->AddRectFilled(p0, p1, pal[color]);
    }

    static float Lerp(float a, float b, float t) {
        return a + (b - a) * t;
    }

    static float ClampFloat(float value, float minValue, float maxValue) {
        if (value < minValue) {
            return minValue;
        }
        if (value > maxValue) {
            return maxValue;
        }
        return value;
    }

    static void DrawOwl(ImDrawList* dl, const ImVec2& base, float pixelSize, float now, float lookX, float lookY, const ImU32* pal) {
        // --- 1. Branch/twigs drawn FIRST so the owl body sits in front ---
        // Derive branch colors from ImGui's current style so they blend with the UI.
        // Outer bark = WindowBg darkened and at 85% alpha.
        // Inner highlight = Border color at 75% alpha mixed with owl outline tint.
        const auto& sc = ImGui::GetStyle().Colors;
        const ImVec4& bgv  = sc[ImGuiCol_WindowBg];
        const ImVec4& brdv = sc[ImGuiCol_Border];
        const ImVec4& outv = sc[ImGuiCol_FrameBg];

        // Bark outer: window bg darkened ~30%, 85% alpha
        const ImU32 barkOuter = IM_COL32(
            static_cast<int>(bgv.x * 178),
            static_cast<int>(bgv.y * 178),
            static_cast<int>(bgv.z * 178),
            215);
        // Bark inner: frame bg + border tint, 78% alpha — slightly lighter
        const ImU32 barkInner = IM_COL32(
            static_cast<int>((outv.x * 0.55f + brdv.x * 0.45f) * 255),
            static_cast<int>((outv.y * 0.55f + brdv.y * 0.45f) * 255),
            static_cast<int>((outv.z * 0.55f + brdv.z * 0.45f) * 255),
            200);
        // Knot dots/twig tips: owl outline color at 80% alpha for cohesion
        const ImU32 knotCol = (pal[O] & 0x00FFFFFFu) | 0xCC000000u;

        const float perchY = base.y + 19.5f * pixelSize + sinf(now * 2.0f) * pixelSize * 0.35f;
        const ImVec2 branchStart(base.x - 5.0f  * pixelSize, perchY + 1.0f  * pixelSize);
        const ImVec2 branchEnd  (base.x + 23.0f * pixelSize, perchY + 0.2f  * pixelSize);
        const ImVec2 branchC1   (base.x + 2.0f  * pixelSize, perchY - 0.4f  * pixelSize);
        const ImVec2 branchC2   (base.x + 14.5f * pixelSize, perchY + 1.6f  * pixelSize);
        dl->AddBezierCubic(branchStart, branchC1, branchC2, branchEnd, barkOuter, pixelSize * 2.6f);
        dl->AddBezierCubic(branchStart, branchC1, branchC2, branchEnd, barkInner, pixelSize * 1.4f);

        const ImVec2 twig1a(base.x + 2.0f  * pixelSize, perchY + 0.2f  * pixelSize);
        const ImVec2 twig1b(base.x - 1.0f  * pixelSize, perchY - 2.0f  * pixelSize);
        const ImVec2 twig2a(base.x + 14.0f * pixelSize, perchY + 0.4f  * pixelSize);
        const ImVec2 twig2b(base.x + 17.5f * pixelSize, perchY - 2.8f  * pixelSize);
        dl->AddLine(twig1a, twig1b, barkOuter, pixelSize * 0.9f);
        dl->AddLine(twig2a, twig2b, barkOuter, pixelSize * 0.9f);
        dl->AddCircleFilled(ImVec2(base.x + 0.0f  * pixelSize, perchY - 2.4f * pixelSize), pixelSize * 0.85f, knotCol);
        dl->AddCircleFilled(ImVec2(base.x + 18.0f * pixelSize, perchY - 3.0f * pixelSize), pixelSize * 0.75f, knotCol);

        // --- 2. Owl body sprite (drawn on top of branch) ---
        DrawSprite(dl, base, pixelSize, Owl, pal);

        // --- 3. Eyes / pupils ---
        const bool blink = fmodf(now + 0.2f, 5.0f) < 0.12f;
        const int pupilOffsetX = (lookX > 0.3f) ? 1 : (lookX < -0.3f ? -1 : 0);
        const int pupilOffsetY = (lookY > 0.2f) ? 1 : (lookY < -0.2f ? -1 : 0);
        const int leftEyeX  = 4;
        const int rightEyeX = 12;
        const int eyeY = 6; // shifted down 1 to match new sprite

        if (blink) {
            for (int i = 0; i < 5; i++) {
                DrawPixel(dl, base, pixelSize, leftEyeX  - 1 + i, eyeY + 2, O, pal);
                DrawPixel(dl, base, pixelSize, rightEyeX - 1 + i, eyeY + 2, O, pal);
            }
        }
        else {
            DrawPixel(dl, base, pixelSize, leftEyeX  + pupilOffsetX,     eyeY + 1 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, leftEyeX  + 1 + pupilOffsetX, eyeY + 1 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, leftEyeX  + pupilOffsetX,     eyeY + 2 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, leftEyeX  + 1 + pupilOffsetX, eyeY + 2 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, rightEyeX + pupilOffsetX,     eyeY + 1 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, rightEyeX + 1 + pupilOffsetX, eyeY + 1 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, rightEyeX + pupilOffsetX,     eyeY + 2 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, rightEyeX + 1 + pupilOffsetX, eyeY + 2 + pupilOffsetY, P, pal);
            DrawPixel(dl, base, pixelSize, leftEyeX  + 2, eyeY + 1, S, pal);
            DrawPixel(dl, base, pixelSize, rightEyeX + 2, eyeY + 1, S, pal);
        }

        // --- 4. Blush dots (below eyes) ---
        const float blushR = pixelSize * 0.85f;
        dl->AddCircleFilled(ImVec2(base.x + 3.5f  * pixelSize, base.y + 11.0f * pixelSize), blushR, pal[K]);
        dl->AddCircleFilled(ImVec2(base.x + 5.2f  * pixelSize, base.y + 11.0f * pixelSize), blushR, pal[K]);
        dl->AddCircleFilled(ImVec2(base.x + 13.0f * pixelSize, base.y + 11.0f * pixelSize), blushR, pal[K]);
        dl->AddCircleFilled(ImVec2(base.x + 14.7f * pixelSize, base.y + 11.0f * pixelSize), blushR, pal[K]);

        // --- 5. Claws redrawn ON TOP of branch to appear in front ---
        for (int y = ClawStartRow; y < OwlH; y++) {
            for (int x = 0; x < OwlW; x++) {
                const uint8_t c = Owl[y][x];
                if (c == _) continue;
                DrawPixel(dl, base, pixelSize, x, y, c, pal);
            }
        }
    }

    void Render() {
        const ImGuiViewport* vp = ImGui::GetMainViewport();
        ImDrawList* dl = ImGui::GetForegroundDrawList();
        const float pixelSize = 3.0f;
        const float padding = 10.0f;
        const float owlW = OwlW * pixelSize;  // now 20 * 4 = 80px
        const float owlH = OwlH * pixelSize;  // now 20 * 4 = 80px
        const float now = static_cast<float>(ImGui::GetTime());
        const float dt = ImGui::GetIO().DeltaTime;

        static float lookX = 0.0f;
        static float lookY = 0.0f;

        const bool followCursor = ImGui::IsMousePosValid();

        const ImVec2 base(
            vp->WorkPos.x + vp->WorkSize.x - owlW - padding,
            vp->WorkPos.y + padding + sinf(now * 2.0f) * 1.2f);

        float targetX = 0.0f;
        float targetY = 0.0f;
        const ImVec2 owlCenter(base.x + owlW * 0.5f, base.y + owlH * 0.42f);
        if (followCursor) {
            const ImVec2 mouse = ImGui::GetMousePos();
            targetX = ClampFloat((mouse.x - owlCenter.x) / 160.0f, -1.0f, 1.0f);
            targetY = ClampFloat((mouse.y - owlCenter.y) / 140.0f, -0.8f, 0.8f);
        }

        const float blend = ClampFloat(dt * 7.0f, 0.0f, 1.0f);
        lookX = Lerp(lookX, targetX, blend);
        lookY = Lerp(lookY, targetY, blend);

        // Resolve palette from the active theme each frame
        const Theme theme = Globals::Get().GetTabManager().GetTheme();
        const ImU32* pal = GetPalette(theme);

        DrawOwl(dl, base, pixelSize, now, lookX, lookY, pal);
    }

} // namespace PixelOwl