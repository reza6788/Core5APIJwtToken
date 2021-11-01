using System;
using System.Linq;
using System.Threading.Tasks;
using JWTAuthentication.Data;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TodoController : ControllerBase
    {
        private readonly ApiDbContext _apiDbContext;

        public TodoController(ApiDbContext apiDbContext)
        {
            _apiDbContext = apiDbContext;
        }

        [HttpGet]
        public async Task<IActionResult> GetItems()
        {
            var items = await _apiDbContext.Items.ToListAsync();
            return Ok(items);
        }

        [AllowAnonymous]
        [HttpGet("{id}")]
        public async Task<IActionResult> GetItem(int id)
        {
            var item = await _apiDbContext.Items.Where(p => p.Id == id).FirstOrDefaultAsync();
            if (item == null)
                return NotFound();
            return Ok(item);
        }

        [HttpPost]
        public async Task<IActionResult> AddItem(ItemData newItem)
        {
            if (ModelState.IsValid)
            {
                await _apiDbContext.Items.AddAsync(newItem);
                await _apiDbContext.SaveChangesAsync();

                return CreatedAtAction("GetItem", new { newItem.Id }, newItem);
            }
            return new JsonResult("Someting went wrong") { StatusCode = 500 };
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> EditItem(int id, ItemData newItem)
        {
            if (id != newItem.Id)
                return BadRequest();

            var item = await _apiDbContext.Items.Where(p => p.Id == id).FirstOrDefaultAsync();
            if (item == null)
                return NotFound();

            item.Title = newItem.Title;
            item.Description = newItem.Description;
            item.Done = newItem.Done;

            await _apiDbContext.SaveChangesAsync();
            return CreatedAtAction("GetItem", new { newItem.Id }, newItem);

            //return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            var item = await _apiDbContext.Items.Where(p => p.Id == id).FirstOrDefaultAsync();
            if (item == null)
                return NotFound();

            _apiDbContext.Items.Remove(item);
            await _apiDbContext.SaveChangesAsync();
            return Ok(item);
        }
    }
}
