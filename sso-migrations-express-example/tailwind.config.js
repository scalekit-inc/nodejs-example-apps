/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./views/**/*.ejs"],
  theme: {
    extend: {
      colors: {
        // Primary Palette - Indigo Blue
        'primary-indigo': {
          50: '#edefff',
          75: '#b7bdff',
          100: '#99a2ff',
          200: '#6d79ff',
          300: '#4f5eff',
          400: '#3742b3',
          500: '#30399c',
        },
        // Primary Palette - Graphite
        'primary-graphite': {
          50: '#e7e7e8',
          75: '#9b9c9f',
          100: '#727378',
          200: '#35363e',
          300: '#0c0d16',
          400: '#08090f',
          500: '#07080d',
        },
        // Primary Palette - Purple
        'primary-purple': {
          50: '#f6f1ff',
          75: '#d8c6ff',
          100: '#c4aeff',
          200: '#b1b8ff',
          300: '#a173ff',
          400: '#7151b3',
          500: '#62469c',
        },
        // Primary Palette - Grey
        'primary-grey': {
          50: '#fdfdfe',
          75: '#f7f7f9',
          100: '#f4f3f6',
          200: '#eefef3',
          300: '#ecebf0',
          400: '#a5a5a8',
          500: '#908f92',
        },
        // Secondary Palette - Yellow
        'secondary-yellow': {
          light: '#fffce7',
          'light-hover': '#fffddb',
          'light-active': '#fffbd5',
          normal: '#ffe110',
          'normal-hover': '#e6cb0e',
          'normal-active': '#ccb40d',
          dark: '#fba90c',
          'dark-hover': '#99870a',
          'dark-active': '#736507',
          darker: '#594f06',
        },
        // Secondary Palette - Green
        'secondary-green': {
          light: '#ecfbeb',
          'light-hover': '#e2f8e1',
          'light-active': '#c4f1c2',
          normal: '#40d239',
          'normal-hover': '#3abd33',
          'normal-active': '#33a82e',
          dark: '#309e2b',
          'dark-hover': '#267e22',
          'dark-active': '#1d5e1a',
          darker: '#164a14',
        },
        // Secondary Palette - Orange
        'secondary-orange': {
          light: '#ffefe6',
          'light-hover': '#ffe7d9',
          'light-active': '#ffceb1',
          normal: '#ff6002',
          'normal-hover': '#e65002',
          'normal-active': '#cc4002',
          dark: '#bf4802',
          'dark-hover': '#993a01',
          'dark-active': '#732b01',
          darker: '#592201',
        },
        // Secondary Palette - Blue
        'secondary-blue': {
          light: '#e7edf6',
          'light-hover': '#dbe4f2',
          'light-active': '#b4c4e4',
          normal: '#0e4a89',
          'normal-hover': '#0d4198',
          'normal-active': '#0b3a87',
          dark: '#0b367f',
          'dark-hover': '#082b65',
          'dark-active': '#062d4c',
          darker: '#05193b',
        },
        // Secondary Palette - Blue (Second Set)
        'secondary-blue-2': {
          light: '#eaf9fd',
          'light-hover': '#dff5fc',
          'light-active': '#bcebf8',
          normal: '#28bfe8',
          'normal-hover': '#24acd1',
          'normal-active': '#209b9a',
          dark: '#1e8fae',
          'dark-hover': '#18738b',
          'dark-active': '#125668',
          darker: '#0e4351',
        },
        // Semantic Palette
        semantic: {
          green: '#36b37e',
          orange: '#ff5631',
          purple: '#6554c0',
        },
      },
    },
  },
  plugins: [],
}