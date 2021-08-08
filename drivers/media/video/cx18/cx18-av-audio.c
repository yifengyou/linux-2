/*
 *  cx18 ADEC audio functions
 *
 *  Derived from cx25840-audio.c
 *
 *  Copyright (C) 2007  Hans Verkuil <hverkuil@xs4all.nl>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#include "cx18-driver.h"

static int set_audclk_freq(struct cx18 *cx, u32 freq)
{
	struct cx18_av_state *state = &cx->av_state;

	if (freq != 32000 && freq != 44100 && freq != 48000)
		return -EINVAL;

	/* common for all inputs and rates */
	/* SA_MCLK_SEL=1, SA_MCLK_DIV=0x10 */
	cx18_av_write(cx, 0x127, 0x50);

	if (state->aud_input != CX18_AV_AUDIO_SERIAL) {
		switch (freq) {
		case 32000:
			/* VID_PLL and AUX_PLL */
			cx18_av_write4(cx, 0x108, 0x1006040f);

			/* AUX_PLL_FRAC */
			cx18_av_write4(cx, 0x110, 0x01bb39ee);

			/* src3/4/6_ctl = 0x0801f77f */
			cx18_av_write4(cx, 0x900, 0x0801f77f);
			cx18_av_write4(cx, 0x904, 0x0801f77f);
			cx18_av_write4(cx, 0x90c, 0x0801f77f);
			break;

		case 44100:
			/* VID_PLL and AUX_PLL */
			cx18_av_write4(cx, 0x108, 0x1009040f);

			/* AUX_PLL_FRAC */
			cx18_av_write4(cx, 0x110, 0x00ec6bd6);

			/* src3/4/6_ctl = 0x08016d59 */
			cx18_av_write4(cx, 0x900, 0x08016d59);
			cx18_av_write4(cx, 0x904, 0x08016d59);
			cx18_av_write4(cx, 0x90c, 0x08016d59);
			break;

		case 48000:
			/* VID_PLL and AUX_PLL */
			cx18_av_write4(cx, 0x108, 0x100a040f);

			/* AUX_PLL_FRAC */
			cx18_av_write4(cx, 0x110, 0x0098d6e5);

			/* src3/4/6_ctl = 0x08014faa */
			cx18_av_write4(cx, 0x900, 0x08014faa);
			cx18_av_write4(cx, 0x904, 0x08014faa);
			cx18_av_write4(cx, 0x90c, 0x08014faa);
			break;
		}
	} else {
		switch (freq) {
		case 32000:
			/* VID_PLL and AUX_PLL */
			cx18_av_write4(cx, 0x108, 0x1e08040f);

			/* AUX_PLL_FRAC */
			cx18_av_write4(cx, 0x110, 0x012a0869);

			/* src1_ctl = 0x08010000 */
			cx18_av_write4(cx, 0x8f8, 0x08010000);

			/* src3/4/6_ctl = 0x08020000 */
			cx18_av_write4(cx, 0x900, 0x08020000);
			cx18_av_write4(cx, 0x904, 0x08020000);
			cx18_av_write4(cx, 0x90c, 0x08020000);

			/* SA_MCLK_SEL=1, SA_MCLK_DIV=0x14 */
			cx18_av_write(cx, 0x127, 0x54);
			break;

		case 44100:
			/* VID_PLL and AUX_PLL */
			cx18_av_write4(cx, 0x108, 0x1809040f);

			/* AUX_PLL_FRAC */
			cx18_av_write4(cx, 0x110, 0x00ec6bd6);

			/* src1_ctl = 0x08010000 */
			cx18_av_write4(cx, 0x8f8, 0x080160cd);

			/* src3/4/6_ctl = 0x08020000 */
			cx18_av_write4(cx, 0x900, 0x08017385);
			cx18_av_write4(cx, 0x904, 0x08017385);
			cx18_av_write4(cx, 0x90c, 0x08017385);
			break;

		case 48000:
			/* VID_PLL and AUX_PLL */
			cx18_av_write4(cx, 0x108, 0x180a040f);

			/* AUX_PLL_FRAC */
			cx18_av_write4(cx, 0x110, 0x0098d6e5);

			/* src1_ctl = 0x08010000 */
			cx18_av_write4(cx, 0x8f8, 0x08018000);

			/* src3/4/6_ctl = 0x08020000 */
			cx18_av_write4(cx, 0x900, 0x08015555);
			cx18_av_write4(cx, 0x904, 0x08015555);
			cx18_av_write4(cx, 0x90c, 0x08015555);
			break;
		}
	}

	state->audclk_freq = freq;

	return 0;
}

void cx18_av_audio_set_path(struct cx18 *cx)
{
	struct cx18_av_state *state = &cx->av_state;

	/* stop microcontroller */
	cx18_av_and_or(cx, 0x803, ~0x10, 0);

	/* assert soft reset */
	cx18_av_and_or(cx, 0x810, ~0x1, 0x01);

	/* Mute everything to prevent the PFFT! */
	cx18_av_write(cx, 0x8d3, 0x1f);

	if (state->aud_input == CX18_AV_AUDIO_SERIAL) {
		/* Set Path1 to Serial Audio Input */
		cx18_av_write4(cx, 0x8d0, 0x01011012);

		/* The microcontroller should not be started for the
		 * non-tuner inputs: autodetection is specific for
		 * TV audio. */
	} else {
		/* Set Path1 to Analog Demod Main Channel */
		cx18_av_write4(cx, 0x8d0, 0x1f063870);
	}

	set_audclk_freq(cx, state->audclk_freq);

	/* deassert soft reset */
	cx18_av_and_or(cx, 0x810, ~0x1, 0x00);

	if (state->aud_input != CX18_AV_AUDIO_SERIAL) {
		/* When the microcontroller detects the
		 * audio format, it will unmute the lines */
		cx18_av_and_or(cx, 0x803, ~0x10, 0x10);
	}
}

static int get_volume(struct cx18 *cx)
{
	/* Volume runs +18dB to -96dB in 1/2dB steps
	 * change to fit the msp3400 -114dB to +12dB range */

	/* check PATH1_VOLUME */
	int vol = 228 - cx18_av_read(cx, 0x8d4);
	vol = (vol / 2) + 23;
	return vol << 9;
}

static void set_volume(struct cx18 *cx, int volume)
{
	/* First convert the volume to msp3400 values (0-127) */
	int vol = volume >> 9;
	/* now scale it up to cx18_av values
	 * -114dB to -96dB maps to 0
	 * this should be 19, but in my testing that was 4dB too loud */
	if (vol <= 23)
		vol = 0;
	else
		vol -= 23;

	/* PATH1_VOLUME */
	cx18_av_write(cx, 0x8d4, 228 - (vol * 2));
}

static int get_bass(struct cx18 *cx)
{
	/* bass is 49 steps +12dB to -12dB */

	/* check PATH1_EQ_BASS_VOL */
	int bass = cx18_av_read(cx, 0x8d9) & 0x3f;
	bass = (((48 - bass) * 0xffff) + 47) / 48;
	return bass;
}

static void set_bass(struct cx18 *cx, int bass)
{
	/* PATH1_EQ_BASS_VOL */
	cx18_av_and_or(cx, 0x8d9, ~0x3f, 48 - (bass * 48 / 0xffff));
}

static int get_treble(struct cx18 *cx)
{
	/* treble is 49 steps +12dB to -12dB */

	/* check PATH1_EQ_TREBLE_VOL */
	int treble = cx18_av_read(cx, 0x8db) & 0x3f;
	treble = (((48 - treble) * 0xffff) + 47) / 48;
	return treble;
}

static void set_treble(struct cx18 *cx, int treble)
{
	/* PATH1_EQ_TREBLE_VOL */
	cx18_av_and_or(cx, 0x8db, ~0x3f, 48 - (treble * 48 / 0xffff));
}

static int get_balance(struct cx18 *cx)
{
	/* balance is 7 bit, 0 to -96dB */

	/* check PATH1_BAL_LEVEL */
	int balance = cx18_av_read(cx, 0x8d5) & 0x7f;
	/* check PATH1_BAL_LEFT */
	if ((cx18_av_read(cx, 0x8d5) & 0x80) == 0)
		balance = 0x80 - balance;
	else
		balance = 0x80 + balance;
	return balance << 8;
}

static void set_balance(struct cx18 *cx, int balance)
{
	int bal = balance >> 8;
	if (bal > 0x80) {
		/* PATH1_BAL_LEFT */
		cx18_av_and_or(cx, 0x8d5, 0x7f, 0x80);
		/* PATH1_BAL_LEVEL */
		cx18_av_and_or(cx, 0x8d5, ~0x7f, bal & 0x7f);
	} else {
		/* PATH1_BAL_LEFT */
		cx18_av_and_or(cx, 0x8d5, 0x7f, 0x00);
		/* PATH1_BAL_LEVEL */
		cx18_av_and_or(cx, 0x8d5, ~0x7f, 0x80 - bal);
	}
}

static int get_mute(struct cx18 *cx)
{
	/* check SRC1_MUTE_EN */
	return cx18_av_read(cx, 0x8d3) & 0x2 ? 1 : 0;
}

static void set_mute(struct cx18 *cx, int mute)
{
	struct cx18_av_state *state = &cx->av_state;

	if (state->aud_input != CX18_AV_AUDIO_SERIAL) {
		/* Must turn off microcontroller in order to mute sound.
		 * Not sure if this is the best method, but it does work.
		 * If the microcontroller is running, then it will undo any
		 * changes to the mute register. */
		if (mute) {
			/* disable microcontroller */
			cx18_av_and_or(cx, 0x803, ~0x10, 0x00);
			cx18_av_write(cx, 0x8d3, 0x1f);
		} else {
			/* enable microcontroller */
			cx18_av_and_or(cx, 0x803, ~0x10, 0x10);
		}
	} else {
		/* SRC1_MUTE_EN */
		cx18_av_and_or(cx, 0x8d3, ~0x2, mute ? 0x02 : 0x00);
	}
}

int cx18_av_audio(struct cx18 *cx, unsigned int cmd, void *arg)
{
	struct cx18_av_state *state = &cx->av_state;
	struct v4l2_control *ctrl = arg;
	int retval;

	switch (cmd) {
	case VIDIOC_INT_AUDIO_CLOCK_FREQ:
		if (state->aud_input != CX18_AV_AUDIO_SERIAL) {
			cx18_av_and_or(cx, 0x803, ~0x10, 0);
			cx18_av_write(cx, 0x8d3, 0x1f);
		}
		cx18_av_and_or(cx, 0x810, ~0x1, 1);
		retval = set_audclk_freq(cx, *(u32 *)arg);
		cx18_av_and_or(cx, 0x810, ~0x1, 0);
		if (state->aud_input != CX18_AV_AUDIO_SERIAL)
			cx18_av_and_or(cx, 0x803, ~0x10, 0x10);
		return retval;

	case VIDIOC_G_CTRL:
		switch (ctrl->id) {
		case V4L2_CID_AUDIO_VOLUME:
			ctrl->value = get_volume(cx);
			break;
		case V4L2_CID_AUDIO_BASS:
			ctrl->value = get_bass(cx);
			break;
		case V4L2_CID_AUDIO_TREBLE:
			ctrl->value = get_treble(cx);
			break;
		case V4L2_CID_AUDIO_BALANCE:
			ctrl->value = get_balance(cx);
			break;
		case V4L2_CID_AUDIO_MUTE:
			ctrl->value = get_mute(cx);
			break;
		default:
			return -EINVAL;
		}
		break;

	case VIDIOC_S_CTRL:
		switch (ctrl->id) {
		case V4L2_CID_AUDIO_VOLUME:
			set_volume(cx, ctrl->value);
			break;
		case V4L2_CID_AUDIO_BASS:
			set_bass(cx, ctrl->value);
			break;
		case V4L2_CID_AUDIO_TREBLE:
			set_treble(cx, ctrl->value);
			break;
		case V4L2_CID_AUDIO_BALANCE:
			set_balance(cx, ctrl->value);
			break;
		case V4L2_CID_AUDIO_MUTE:
			set_mute(cx, ctrl->value);
			break;
		default:
			return -EINVAL;
		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
}
